import { Bot, Button, Embed, Row } from './yapper.js';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createServer } from 'node:http';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

try {
  const envText = readFileSync(new URL('./.env', import.meta.url), 'utf8');
  for (const line of envText.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}

const token = process.env.YAPPER_BOT_TOKEN || process.env.BOT_TOKEN;
if (!token) {
  console.error('Set YAPPER_BOT_TOKEN (or BOT_TOKEN) in AntiAlt/.env before starting.');
  process.exit(1);
}

const bot = new Bot(token);
const DATA_DIR = new URL('./data/', import.meta.url);
const VERIFY_FILE = new URL('./data/verified-users.json', import.meta.url);
const CONSENT_FILE = new URL('./data/consents.json', import.meta.url);
const SETTINGS_FILE = new URL('./data/server-settings.json', import.meta.url);
const OAUTH_CLIENT_ID = process.env.AUTH_TOKEN_WEBSITE_CLIENT_ID;
const OAUTH_TOKEN_ENDPOINT = process.env.AUTH_TOKEN_WEBSITE_TOKEN_ENDPOINT || 'https://www.yapin.gg/api/oauth/token';
const OAUTH_IDENTITY_ENDPOINT = process.env.AUTH_TOKEN_WEBSITE_IDENTITY_ENDPOINT || 'https://www.yapin.gg/api/oauth/me';
const OAUTH_CALLBACK = process.env.AUTH_TOKEN_WEBSITE_CALLBACK || 'http://localhost:9283/callback';
const OAUTH_PORT = Number(process.env.ANTIALT_HTTP_PORT || new URL(OAUTH_CALLBACK).port || 9283);
const OAUTH_BIND_HOST = process.env.ANTIALT_BIND_HOST || '127.0.0.1';
const IP_HASH_KEY_FILE = new URL('./data/ip-hash-key.bin', import.meta.url);
const VPN_CACHE_FILE = new URL('./data/vpn-ip-ranges.txt', import.meta.url);
const VPN_LIST_URLS = [
  'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt',
  'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt',
];
const VPN_LIST_REFRESH_MS = 12 * 60 * 60 * 1000;
let vpnRanges = [];
let ipHashKey;
const pendingAuthStart = new Map();
const pendingOAuth = new Map();
const pendingConsent = new Map();
let verifiedUsers = {};
let consents = {};
let serverSettings = {};

function readJson(url, label) {
  try { return JSON.parse(readFileSync(url, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return {};
    throw new Error(`Could not read ${label}: ${error.message}`);
  }
}
verifiedUsers = readJson(VERIFY_FILE, 'verified-users.json');
consents = readJson(CONSENT_FILE, 'consents.json');
serverSettings = readJson(SETTINGS_FILE, 'server-settings.json');

const LANGUAGES = {
  en: {
    name: 'English',
    setupServerOnly: 'This command only works in a server.',
    missingManageChannels: 'I need the **Manage Channels** permission to create the verification channel.',
    channelCreateFailed: (reason) => `I could not create the channel: ${reason}`,
    verifyTitle: 'AntiAlt Verification',
    verifyDescription: 'Click Verify to authenticate your Yapin’ account. After sign-in, you will be asked to accept the Terms of Service and Privacy Notice. After you accept, AntiAlt stores your server ID, authenticated account ID, a hash of a random browser cookie, and a keyed hash of your IP address to prevent repeat verification from the same browser or IP. No raw IP or hardware identifier is stored.',
    termsTitle: 'Terms of Service',
    termsText: 'By continuing, you agree to use AntiAlt only for server safety and to provide accurate account information. Verification is limited to one Yapin’ account per server, IP address, and browser profile. AntiAlt also checks the callback IP against a public list of known VPN networks; a match blocks verification. People sharing an IP address, VPN, or network may be grouped and blocked together. A browser profile is not a physical-device identifier. Server administrators control this bot and its verification settings.',
    privacyTitle: 'Privacy Notice',
    privacyText: 'After you accept, AntiAlt stores your Yapin’ account ID and username, server ID, consent and verification timestamps, plus a SHA-256 hash of a random first-party browser cookie and a keyed HMAC-SHA-256 hash of the IP address observed by the callback after consent. Raw IP addresses are not stored. The IP is also checked locally against the public X4BNet VPN network list downloaded from GitHub; it is not sent to a separate IP lookup service. A match blocks verification. Browser hashes do not identify physical hardware and do not work across browsers. Shared IPs, VPNs, or networks can cause accounts to be grouped. The bot operator can access these records. Ask the server administrators to request deletion.',
    consentQuestion: 'Do you accept our Terms of Service & Privacy Policy?',
    consentYes: 'Yes, I accept',
    consentNo: 'No, I do not accept',
    consentDeclined: 'You declined. No verification data was saved.',
    oauthComplete: 'Sign-in and consent are complete. You can return to the server.',
    oauthSetupMissing: 'OAuth sign-in needs token and identity endpoint URLs configured by the bot operator.',
    oauthStart: (url) => `Your secure sign-in link (valid for 15 minutes): ${url}`,
    deviceRefresh: (url) => `You're already verified. Accept the updated Privacy Notice here to activate browser duplicate checks: ${url}`,
    duplicateBrowserTitle: 'Alt Account Attempt Blocked',
    duplicateBrowser: 'This account matched a previous verification from this server by IP hash or browser profile. It was not verified, and its verification role was removed if it had one. AntiAlt stores a keyed IP hash and browser-cookie hash, not the raw IP or a hardware ID. Shared networks can cause false positives; contact a server administrator if you think this is a mistake.',
    oauthNotConfigured: 'OAuth sign-in is not configured. Please ask a server admin for help.',
    oauthSuccess: 'Your Yapin’ account has been verified for this server.',
    oauthFailure: 'Sign-in could not be completed or expired. Click Verify to start again.',
    oauthAccountMismatch: 'This Yapin’ account does not match the account that clicked Verify. Sign into the correct account and start verification again from the server.',
    verifyButton: 'Verify',
    setupDone: (channelId, roleName, roleReady) => `AntiAlt is set up: <#${channelId}>. ${roleReady ? `Verified members will get the **${roleName}** role.` : `Create the **${roleName}** role in server settings; the bot API cannot create roles.`}`,
    roleSetupFailed: 'I could not save the authenticated role setting. Please check the bot logs.',
    roleCreateUnsupported: (name) => `I cannot create **${name}** because Yapin’ does not expose a role-creation endpoint to bots. Create it in Server Settings → Roles, then run /setup-antialtrole again.`,
    roleConfigured: (name) => `The **${name}** role is configured. I will assign it after verification.`,
    roleAssignFailed: 'Your account is verified, but I could not assign the role. Please ask a server admin to check my Manage Roles permission and role order.',
    channelPostFailed: (channelId) => `I created <#${channelId}>, but I cannot post there. I may need **Send Messages** permission.`,
    verificationUnmatched: 'I could not match this verification to a server.',
    alreadyVerified: () => `You're already verified!`,
    alreadyVerifiedRoleAdded: () => `You're already verified! I've added your Authenticated role.`,
    authenticatedRoleMissing: (name) => `You're already verified, but I couldn't find the **${name}** role. Ask a server admin to create it.`,
    verified: (username) => `Verified as **${username}**. This verification is stored for this server only.`,
    saveFailed: 'I could not save your verification right now. Please try again later.',
    vpnBlocked: 'Verification blocked: this IP matches a known VPN network. Disconnect from the VPN and try again. If this is a mistake, contact a server administrator.',
    manualUsage: 'Usage: `/manual-verify username` or `/manual-unverify username`.',
    manualOwnerOnly: 'Only this server’s owner can use manual verification commands.',
    memberNotFound: (name) => `I could not find **${name}** in this server. Use the exact Yapin’ username or a user ID.`,
    manualVerified: (name) => `Manually verified **${name}** and assigned the Authenticated role if it is configured.`,
    manualAlreadyVerified: (name) => `**${name}** is already verified.`,
    manualUnverified: (name) => `Unverified **${name}** and removed the Authenticated role if they had it.`,
    manualNotVerified: (name) => `**${name}** did not have a saved verification.`,
    roleRemoveFailed: 'The verification was removed, but I could not remove the role. Please check my Manage Roles permission and role order.',
    languageUsage: 'Choose a language: `/language en`, `/language de`, or `/language es`.',
    languageSaved: (name) => `AntiAlt will now speak ${name} in this server.`,
  },
  de: {
    name: 'Deutsch',
    setupServerOnly: 'Dieser Befehl funktioniert nur in einem Server.',
    missingManageChannels: 'Mir fehlt die Berechtigung **Kanäle verwalten**, um den Verifizierungskanal zu erstellen.',
    channelCreateFailed: (reason) => `Der Kanal konnte nicht erstellt werden: ${reason}`,
    verifyTitle: 'AntiAlt-Verifizierung',
    verifyDescription: 'Klicke auf Verifizieren, um deinen Yapin’-Account anzumelden. Nach der Anmeldung wirst du gefragt, ob du den Nutzungsbedingungen und dem Datenschutzhinweis zustimmst. Nach deiner Zustimmung speichert AntiAlt Server-ID, bestätigte Account-ID, einen Hash eines zufälligen Browser-Cookies und einen keyed HMAC-SHA-256-Hash der vom Callback erkannten IP-Adresse, um Wiederholungen aus demselben Browser oder derselben IP zu verhindern. Rohe IP-Adressen und Hardware-Kennungen werden nicht gespeichert.',
    termsTitle: 'Nutzungsbedingungen',
    termsText: 'Wenn du fortfährst, stimmst du zu, AntiAlt nur zur Sicherheit des Servers zu nutzen und korrekte Account-Informationen anzugeben. Die Verifizierung ist auf einen Yapin’-Account pro Server, IP-Adresse und Browserprofil begrenzt. Zusätzlich vergleicht AntiAlt die Callback-IP mit einer öffentlichen Liste bekannter VPN-Netzwerke; ein Treffer blockiert die Verifizierung. Personen mit gemeinsamer IP, VPN oder gemeinsamem Netzwerk können zusammengefasst und blockiert werden. Ein Browserprofil ist keine physische Gerätekennung. Die Server-Admins verwalten diesen Bot und seine Einstellungen.',
    privacyTitle: 'Datenschutzhinweis',
    privacyText: 'Nach deiner Zustimmung speichert AntiAlt deine Yapin’-Account-ID und deinen Nutzernamen, Server-ID, Zustimmungs- und Verifizierungszeitpunkte, einen SHA-256-Hash eines zufälligen Erstanbieter-Browser-Cookies und einen keyed HMAC-SHA-256-Hash der vom Callback erkannten IP-Adresse. Rohe IP-Adressen werden nicht gespeichert. Die IP wird lokal mit der öffentlichen X4BNet-VPN-Netzwerkliste verglichen, die von GitHub geladen wird; sie wird nicht an einen separaten IP-Abfragedienst gesendet. Ein Treffer blockiert die Verifizierung. Browser-Hashes identifizieren keine Hardware und funktionieren nicht browserübergreifend. Gemeinsame IPs, VPNs oder Netzwerke können Accounts zusammenfassen. Der Bot-Betreiber kann auf diese Daten zugreifen. Bitte die Server-Admins um Löschung.',
    consentQuestion: 'Akzeptierst du unsere Nutzungsbedingungen und Datenschutzerklärung?',
    consentYes: 'Ja, ich stimme zu',
    consentNo: 'Nein, ich stimme nicht zu',
    consentDeclined: 'Du hast abgelehnt. Es wurden keine Verifizierungsdaten gespeichert.',
    oauthComplete: 'Anmeldung und Zustimmung sind abgeschlossen. Du kannst zum Server zurückkehren.',
    oauthSetupMissing: 'Für OAuth müssen Token- und Identitäts-Endpunkt-URLs vom Bot-Betreiber eingerichtet werden.',
    oauthStart: (url) => `Dein sicherer Anmeldelink (15 Minuten gültig): ${url}`,
    deviceRefresh: (url) => `Du bist bereits verifiziert. Stimme hier dem aktualisierten Datenschutzhinweis zu, um Browser-Duplikatprüfungen zu aktivieren: ${url}`,
    duplicateBrowserTitle: 'Alt-Account-Versuch blockiert',
    duplicateBrowser: 'Dieser Account stimmt beim IP-Hash oder Browserprofil mit einer früheren Verifizierung in diesem Server überein. Er wurde nicht verifiziert; eine vorhandene Verifizierungsrolle wurde nach Möglichkeit entfernt. AntiAlt speichert einen keyed IP-Hash und Browser-Cookie-Hash, nicht die rohe IP oder eine Hardware-ID. Gemeinsame Netzwerke können Fehlalarme verursachen; wende dich bei einem vermuteten Fehler an einen Server-Admin.',
    oauthNotConfigured: 'OAuth-Anmeldung ist nicht konfiguriert. Bitte wende dich an einen Server-Admin.',
    oauthSuccess: 'Dein Yapin’-Account wurde für diesen Server verifiziert.',
    oauthFailure: 'Die Anmeldung ist fehlgeschlagen oder abgelaufen. Klicke erneut auf Verifizieren.',
    oauthAccountMismatch: 'Dieser Yapin’-Account stimmt nicht mit dem Account überein, der auf Verifizieren geklickt hat. Melde dich mit dem richtigen Account an und starte die Verifizierung erneut im Server.',
    verifyButton: 'Verifizieren',
    setupDone: (channelId, roleName, roleReady) => `AntiAlt ist eingerichtet: <#${channelId}>. ${roleReady ? `Verifizierte Mitglieder erhalten die Rolle **${roleName}**.` : `Lege die Rolle **${roleName}** in den Servereinstellungen an; die Bot-API kann keine Rollen erstellen.`}`,
    roleSetupFailed: 'Die Einstellung für die Authentifiziert-Rolle konnte nicht gespeichert werden. Bitte prüfe die Bot-Logs.',
    roleCreateUnsupported: (name) => `Ich kann **${name}** nicht erstellen, weil Yapin’ Bots keinen Rollen-Erstell-Endpunkt bereitstellt. Lege die Rolle unter Servereinstellungen → Rollen an und führe danach erneut /setup-antialtrole aus.`,
    roleConfigured: (name) => `Die Rolle **${name}** ist eingerichtet. Ich vergebe sie nach der Verifizierung.`,
    roleAssignFailed: 'Dein Account ist verifiziert, aber ich konnte die Rolle nicht vergeben. Bitte prüfe meine Berechtigung „Rollen verwalten“ und die Rollenreihenfolge.',
    channelPostFailed: (channelId) => `Der Kanal <#${channelId}> wurde erstellt, aber ich kann dort nicht posten. Möglicherweise fehlt mir **Nachrichten senden**.`,
    verificationUnmatched: 'Die Verifizierung konnte keinem Server zugeordnet werden.',
    alreadyVerified: () => `Du bist bereits verifiziert!`,
    alreadyVerifiedRoleAdded: () => `Du bist bereits verifiziert! Ich habe dir die Authenticated-Rolle gegeben.`,
    authenticatedRoleMissing: (name) => `Du bist bereits verifiziert, aber ich finde die Rolle **${name}** nicht. Bitte einen Server-Admin, sie anzulegen.`,
    verified: (username) => `Als **${username}** verifiziert. Diese Bestätigung wird nur für diesen Server gespeichert.`,
    saveFailed: 'Deine Verifizierung konnte gerade nicht gespeichert werden. Bitte versuche es später erneut.',
    vpnBlocked: 'Verifizierung blockiert: Diese IP-Adresse stimmt mit einem bekannten VPN-Netzwerk überein. Trenne die VPN-Verbindung und versuche es erneut. Bei einem Fehler wende dich an einen Server-Admin.',
    manualUsage: 'Verwendung: `/manual-verify username` oder `/manual-unverify username`.',
    manualOwnerOnly: 'Nur der Serverinhaber kann manuelle Verifizierungsbefehle verwenden.',
    memberNotFound: (name) => `Ich konnte **${name}** in diesem Server nicht finden. Verwende den exakten Yapin’-Nutzernamen oder eine User-ID.`,
    manualVerified: (name) => `**${name}** wurde manuell verifiziert. Die Authenticated-Rolle wurde vergeben, falls sie eingerichtet ist.`,
    manualAlreadyVerified: (name) => `**${name}** ist bereits verifiziert.`,
    manualUnverified: (name) => `**${name}** wurde unverifiziert und die Authenticated-Rolle wurde gegebenenfalls entfernt.`,
    manualNotVerified: (name) => `Für **${name}** war keine gespeicherte Verifizierung vorhanden.`,
    roleRemoveFailed: 'Die Verifizierung wurde entfernt, aber ich konnte die Rolle nicht entfernen. Bitte prüfe meine Berechtigung „Rollen verwalten“ und die Rollenreihenfolge.',
    languageUsage: 'Wähle eine Sprache: `/language en`, `/language de` oder `/language es`.',
    languageSaved: (name) => `AntiAlt spricht in diesem Server jetzt ${name}.`,
  },
  es: {
    name: 'Español',
    setupServerOnly: 'Este comando solo funciona en un servidor.',
    missingManageChannels: 'Necesito el permiso **Administrar canales** para crear el canal de verificación.',
    channelCreateFailed: (reason) => `No pude crear el canal: ${reason}`,
    verifyTitle: 'Verificación de AntiAlt',
    verifyDescription: 'Pulsa Verificar para autenticar tu cuenta de Yapin’. Después del inicio de sesión, se te preguntará si aceptas los Términos de servicio y el Aviso de privacidad. Tras aceptar, AntiAlt guarda el ID del servidor, el ID de la cuenta, un hash de una cookie aleatoria del navegador y un hash HMAC-SHA-256 con clave de la IP detectada por el callback para impedir verificaciones repetidas desde el mismo navegador o IP. No guarda la IP sin procesar ni identificadores de hardware.',
    termsTitle: 'Términos de servicio',
    termsText: 'Al continuar, aceptas usar AntiAlt solo para la seguridad del servidor y proporcionar información de cuenta correcta. Se limita a una cuenta de Yapin’ por servidor, dirección IP y perfil del navegador. AntiAlt también compara la IP de retorno con una lista pública de redes VPN conocidas; una coincidencia bloquea la verificación. Las personas que compartan IP, VPN o red pueden agruparse y bloquearse juntas. El perfil del navegador no identifica el dispositivo físico. Los administradores controlan este bot y su configuración.',
    privacyTitle: 'Aviso de privacidad',
    privacyText: 'Tras aceptar, AntiAlt guarda tu ID de cuenta de Yapin’, nombre de usuario, ID del servidor, fechas de consentimiento/verificación, un hash SHA-256 de una cookie aleatoria del navegador y un hash HMAC-SHA-256 con clave de la IP observada por el callback. No se guardan IPs sin procesar. La IP se compara localmente con la lista pública de redes VPN de X4BNet descargada desde GitHub; no se envía a otro servicio de consulta. Una coincidencia bloquea la verificación. El hash del navegador no identifica hardware ni funciona entre navegadores. Las IPs, VPNs o redes compartidas pueden agrupar cuentas. El operador del bot puede acceder a estos datos. Solicita su eliminación a los administradores del servidor.',
    consentQuestion: '¿Aceptas nuestros Términos de servicio y Política de privacidad?',
    consentYes: 'Sí, acepto',
    consentNo: 'No, no acepto',
    consentDeclined: 'Has rechazado. No se guardaron datos de verificación.',
    oauthComplete: 'El inicio de sesión y el consentimiento se completaron. Puedes volver al servidor.',
    oauthSetupMissing: 'El operador del bot debe configurar las URL de token e identidad de OAuth.',
    oauthStart: (url) => `Tu enlace seguro de inicio de sesión (válido durante 15 minutos): ${url}`,
    deviceRefresh: (url) => `Ya estás verificado. Acepta aquí el Aviso de privacidad actualizado para activar la detección de duplicados del navegador: ${url}`,
    duplicateBrowserTitle: 'Intento de cuenta alternativa bloqueado',
    duplicateBrowser: 'Esta cuenta coincide con una verificación anterior de este servidor por hash de IP o perfil del navegador. No fue verificada y se quitó su rol si lo tenía. AntiAlt guarda un hash de IP con clave y un hash de cookie, no la IP sin procesar ni una ID de hardware. Las redes compartidas pueden causar falsos positivos; contacta con un administrador si crees que es un error.',
    oauthNotConfigured: 'El inicio de sesión OAuth no está configurado. Pide ayuda a un administrador.',
    oauthSuccess: 'Tu cuenta de Yapin’ se verificó para este servidor.',
    oauthFailure: 'No se pudo completar el inicio de sesión o ha caducado. Pulsa Verificar para intentarlo de nuevo.',
    oauthAccountMismatch: 'Esta cuenta de Yapin’ no coincide con la cuenta que pulsó Verificar. Inicia sesión con la cuenta correcta y vuelve a empezar la verificación desde el servidor.',
    verifyButton: 'Verificar',
    setupDone: (channelId, roleName, roleReady) => `AntiAlt está configurado: <#${channelId}>. ${roleReady ? `Los miembros verificados recibirán el rol **${roleName}**.` : `Crea el rol **${roleName}** en los ajustes del servidor; la API del bot no puede crear roles.`}`,
    roleSetupFailed: 'No pude guardar la configuración del rol. Revisa los registros del bot.',
    roleCreateUnsupported: (name) => `No puedo crear **${name}** porque Yapin’ no ofrece a los bots un endpoint para crear roles. Créalo en Ajustes del servidor → Roles y vuelve a ejecutar /setup-antialtrole.`,
    roleConfigured: (name) => `El rol **${name}** está configurado. Lo asignaré después de la verificación.`,
    roleAssignFailed: 'Tu cuenta está verificada, pero no pude asignar el rol. Pide a un administrador que revise el permiso Administrar roles y el orden de roles.',
    channelPostFailed: (channelId) => `Creé <#${channelId}>, pero no puedo publicar allí. Puede que necesite el permiso **Enviar mensajes**.`,
    verificationUnmatched: 'No pude asociar esta verificación con un servidor.',
    alreadyVerified: () => `¡Ya estás verificado!`,
    alreadyVerifiedRoleAdded: () => `¡Ya estás verificado! Te he asignado el rol Authenticated.`,
    authenticatedRoleMissing: (name) => `Ya estás verificado, pero no encuentro el rol **${name}**. Pide a un administrador que lo cree.`,
    verified: (username) => `Verificado como **${username}**. Esta verificación solo se guarda para este servidor.`,
    saveFailed: 'No pude guardar tu verificación ahora. Inténtalo de nuevo más tarde.',
    vpnBlocked: 'Verificación bloqueada: esta IP coincide con una red VPN conocida. Desconecta la VPN e inténtalo de nuevo. Si es un error, contacta con un administrador.',
    manualUsage: 'Uso: `/manual-verify username` o `/manual-unverify username`.',
    manualOwnerOnly: 'Solo el propietario del servidor puede usar los comandos de verificación manual.',
    memberNotFound: (name) => `No encontré a **${name}** en este servidor. Usa el nombre exacto de Yapin’ o el ID del usuario.`,
    manualVerified: (name) => `Verifiqué manualmente a **${name}** y asigné el rol Authenticated si está configurado.`,
    manualAlreadyVerified: (name) => `**${name}** ya está verificado.`,
    manualUnverified: (name) => `Desverifiqué a **${name}** y quité el rol Authenticated si lo tenía.`,
    manualNotVerified: (name) => `**${name}** no tenía una verificación guardada.`,
    roleRemoveFailed: 'Se quitó la verificación, pero no pude quitar el rol. Revisa el permiso Administrar roles y el orden de roles.',
    languageUsage: 'Elige un idioma: `/language en`, `/language de` o `/language es`.',
    languageSaved: (name) => `AntiAlt hablará ahora en ${name} en este servidor.`,
  },
};

function languageFor(serverId) {
  const code = serverSettings[serverId]?.language;
  return LANGUAGES[code] || LANGUAGES.en;
}
function saveJson(url, data) {
  mkdirSync(DATA_DIR, { recursive: true });
  writeFileSync(url, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}
function saveVerifications() { saveJson(VERIFY_FILE, verifiedUsers); }
function saveConsents() { saveJson(CONSENT_FILE, consents); }
function saveSettings() { saveJson(SETTINGS_FILE, serverSettings); }

function ipToBigInt(rawAddress) {
  let address = String(rawAddress || '').trim().toLowerCase().replace(/^::ffff:/, '');
  const family = isIP(address);
  if (family === 4) return { family, value: address.split('.').reduce((value, octet) => (value << 8n) | BigInt(octet), 0n) };
  if (family !== 6) return null;
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const octets = address.slice(lastColon + 1).split('.').map(Number);
    if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    address = `${address.slice(0, lastColon)}:${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  if (groups.length !== 8 || groups.some((part) => !/^[a-f0-9]{1,4}$/.test(part))) return null;
  return { family, value: groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n) };
}

function parseVpnRanges(text) {
  return String(text).split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((entry) => {
    const [network, prefixText] = entry.split('/');
    const parsed = ipToBigInt(network);
    const prefix = prefixText === undefined ? (parsed?.family === 4 ? 32 : 128) : Number(prefixText);
    const bits = parsed?.family === 4 ? 32 : 128;
    if (!parsed || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
    const shift = BigInt(bits - prefix);
    return { family: parsed.family, start: (parsed.value >> shift) << shift, end: (((parsed.value >> shift) + 1n) << shift) - 1n };
  }).filter(Boolean);
}

function isListedVpnIp(address) {
  const parsed = ipToBigInt(address);
  return !!parsed && vpnRanges.some((range) => range.family === parsed.family && parsed.value >= range.start && parsed.value <= range.end);
}

async function refreshVpnRanges() {
  try {
    const responses = await Promise.all(VPN_LIST_URLS.map((url) => fetch(url, { signal: AbortSignal.timeout(15000) })));
    if (responses.some((response) => !response.ok)) throw new Error(`VPN list download failed (${responses.map((response) => response.status).join(', ')})`);
    const contents = await Promise.all(responses.map((response) => response.text()));
    const combined = contents.join('\n');
    const parsed = parseVpnRanges(combined);
    if (parsed.length < 1000) throw new Error(`VPN list was unexpectedly small (${parsed.length} ranges)`);
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(VPN_CACHE_FILE, combined, 'utf8');
    vpnRanges = parsed;
    console.log(`[AntiAlt] loaded ${vpnRanges.length} VPN network ranges`);
  } catch (error) {
    console.error('[AntiAlt] VPN list refresh failed; using cached list if available:', error.message);
    if (!vpnRanges.length) {
      try { vpnRanges = parseVpnRanges(readFileSync(VPN_CACHE_FILE, 'utf8')); }
      catch (cacheError) {
        if (cacheError.code !== 'ENOENT') console.error('[AntiAlt] could not read VPN list cache:', cacheError.message);
      }
    }
  }
}

try { vpnRanges = parseVpnRanges(readFileSync(VPN_CACHE_FILE, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') console.error('[AntiAlt] could not read VPN list cache:', error.message); }
void refreshVpnRanges();
setInterval(() => { void refreshVpnRanges(); }, VPN_LIST_REFRESH_MS).unref();

async function findServerMember(serverId, query) {
  const normalized = String(query || '').trim().replace(/^<@!?(\d+)>$/, '$1').replace(/^@/, '').toLowerCase();
  if (!normalized) return null;
  const all = [];
  let after;
  for (let page = 0; page < 100; page++) {
    const members = await bot.members(serverId, after);
    if (!Array.isArray(members) || !members.length) break;
    all.push(...members);
    const last = members[members.length - 1];
    after = last.user_id || last.id || last.user?.id;
    if (members.length < 200 || !after) break;
  }
  const details = (member) => {
    const user = member.user || member;
    return { id: String(member.user_id || user.id || member.id || ''), username: String(user.username || member.username || user.display_name || member.display_name || '') };
  };
  return all.map((member) => ({ member, ...details(member) })).find((entry) => entry.id === normalized || entry.username.toLowerCase() === normalized) || null;
}

async function isServerOwner(msg) {
  if (!msg.server_id || !msg.author_id) return false;
  const server = await bot.server(msg.server_id);
  return String(server.owner_id || server.owner?.id || '') === String(msg.author_id);
}

async function removeAuthenticatedRole(serverId, userId) {
  const settings = serverSettings[serverId];
  if (!settings?.authenticatedRoleId) return;
  await bot.removeRole(serverId, userId, settings.authenticatedRoleId);
}

async function ensureAuthenticatedRole(serverId, userId) {
  const settings = serverSettings[serverId];
  const roleName = settings?.authenticatedRoleName;
  if (!roleName) return { status: 'not-configured' };

  const roles = await bot.roles(serverId);
  const role = roles.find((item) => item.id === settings.authenticatedRoleId)
    || roles.find((item) => item.name?.toLowerCase() === roleName.toLowerCase());
  if (!role) return { status: 'missing', roleName };
  if (settings.authenticatedRoleId !== role.id) {
    settings.authenticatedRoleId = role.id;
    saveSettings();
  }

  const member = await bot.member(serverId, userId);
  const memberRoleIds = member.role_ids || (Array.isArray(member.roles) ? member.roles.map((item) => typeof item === 'string' ? item : item.id) : []);
  if (memberRoleIds.includes(role.id)) return { status: 'already-has-role', roleName };
  await bot.addRole(serverId, userId, role.id);
  return { status: 'added', roleName };
}

bot.command('language', 'Set this server language: en, de, or es', async (msg) => {
  const serverId = msg.server_id;
  if (!serverId) return msg.reply(LANGUAGES.en.setupServerOnly, { replyTo: msg.id });
  const input = (msg.args || '').trim().toLowerCase();
  const language = LANGUAGES[input];
  if (!language) return msg.reply(languageFor(serverId).languageUsage, { replyTo: msg.id });
  serverSettings[serverId] = { ...serverSettings[serverId], language: input };
  try { saveSettings(); }
  catch (error) {
    console.error('[AntiAlt] could not save language setting:', error.message);
    return msg.reply(LANGUAGES.en.saveFailed, { replyTo: msg.id });
  }
  return msg.reply(language.languageSaved(language.name), { replyTo: msg.id });
});

bot.command('manual-verify', 'Manually verify a server member by Yapin’ username', async (msg) => {
  const serverId = msg.server_id;
  const language = languageFor(serverId);
  if (!serverId) return msg.reply(language.setupServerOnly, { replyTo: msg.id });
  if (!(await isServerOwner(msg))) return msg.reply(language.manualOwnerOnly, { replyTo: msg.id });
  const query = (msg.args || '').trim();
  if (!query) return msg.reply(language.manualUsage, { replyTo: msg.id });
  const found = await findServerMember(serverId, query);
  if (!found) return msg.reply(language.memberNotFound(query), { replyTo: msg.id });
  const records = verifiedUsers[serverId] ||= {};
  const existing = Object.values(records).find((record) => String(record.requested_by_user_id) === found.id);
  if (existing) {
    try { await ensureAuthenticatedRole(serverId, found.id); }
    catch (error) { console.error('[AntiAlt] manual verify could not restore role:', error.message); }
    return msg.reply(language.manualAlreadyVerified(existing.username || found.username), { replyTo: msg.id });
  }
  const recordId = `manual:${found.id}`;
  records[recordId] = {
    username: found.username || query,
    requested_by_user_id: found.id,
    manual: true,
    fingerprint_version: 2,
    consented_at: null,
    verified_at: new Date().toISOString(),
    terms_version: null,
    privacy_version: null,
  };
  try { saveVerifications(); }
  catch (error) {
    delete records[recordId];
    console.error('[AntiAlt] manual verification could not be saved:', error.message);
    return msg.reply(language.saveFailed, { replyTo: msg.id });
  }
  let roleWarning = '';
  try {
    const result = await ensureAuthenticatedRole(serverId, found.id);
    if (result.status === 'missing') roleWarning = ` ${language.authenticatedRoleMissing(result.roleName)}`;
  } catch (error) {
    console.error('[AntiAlt] manual verification role assignment failed:', error.message);
    roleWarning = ` ${language.roleAssignFailed}`;
  }
  return msg.reply(`${language.manualVerified(found.username || query)}${roleWarning}`, { replyTo: msg.id });
});

bot.command('manual-unverify', 'Manually unverify a server member by Yapin’ username', async (msg) => {
  const serverId = msg.server_id;
  const language = languageFor(serverId);
  if (!serverId) return msg.reply(language.setupServerOnly, { replyTo: msg.id });
  if (!(await isServerOwner(msg))) return msg.reply(language.manualOwnerOnly, { replyTo: msg.id });
  const query = (msg.args || '').trim();
  if (!query) return msg.reply(language.manualUsage, { replyTo: msg.id });
  const found = await findServerMember(serverId, query);
  if (!found) return msg.reply(language.memberNotFound(query), { replyTo: msg.id });
  const records = verifiedUsers[serverId] || {};
  const matchingIds = Object.entries(records)
    .filter(([, record]) => String(record.requested_by_user_id) === found.id)
    .map(([accountId]) => accountId);
  if (!matchingIds.length) return msg.reply(language.manualNotVerified(found.username || query), { replyTo: msg.id });
  const previousRecords = { ...records };
  for (const accountId of matchingIds) delete records[accountId];
  if (!Object.keys(records).length) delete verifiedUsers[serverId];
  try { saveVerifications(); }
  catch (error) {
    verifiedUsers[serverId] = previousRecords;
    console.error('[AntiAlt] manual unverify could not be saved:', error.message);
    return msg.reply(language.saveFailed, { replyTo: msg.id });
  }
  let roleWarning = '';
  try { await removeAuthenticatedRole(serverId, found.id); }
  catch (error) {
    console.error('[AntiAlt] manual unverify could not remove role:', error.message);
    roleWarning = ` ${language.roleRemoveFailed}`;
  }
  return msg.reply(`${language.manualUnverified(found.username || query)}${roleWarning}`, { replyTo: msg.id });
});

bot.command('setup-antialtrole', 'Configure the AntiAlt authenticated role', async (msg) => {
  const serverId = msg.server_id;
  if (!serverId) return msg.reply(LANGUAGES.en.setupServerOnly, { replyTo: msg.id });
  const language = languageFor(serverId);
  const roleName = (msg.args || '').trim() || serverSettings[serverId]?.authenticatedRoleName || 'Authenticated';
  if (roleName.length > 100) return msg.reply('Role names must be 100 characters or fewer.', { replyTo: msg.id });

  let roles;
  try { roles = await bot.roles(serverId); }
  catch (error) {
    const message = error.status === 403
      ? 'I do not have permission to view server roles.'
      : `I could not read server roles: ${error.message}`;
    return msg.reply(message, { replyTo: msg.id });
  }
  const role = roles.find((item) => item.name?.toLowerCase() === roleName.toLowerCase());
  if (!role) return msg.reply(language.roleCreateUnsupported(roleName), { replyTo: msg.id });

  serverSettings[serverId] = { ...serverSettings[serverId], authenticatedRoleName: role.name, authenticatedRoleId: role.id };
  try { saveSettings(); }
  catch (error) {
    console.error('[AntiAlt] could not save role setting:', error.message);
    return msg.reply(language.roleSetupFailed, { replyTo: msg.id });
  }
  return msg.reply(language.roleConfigured(role.name), { replyTo: msg.id });
});

bot.command('setup-antialt', 'Set up AntiAlt verification; optionally pass an authenticated role name', async (msg) => {
  const serverId = msg.server_id;
  if (!serverId) return msg.reply(LANGUAGES.en.setupServerOnly, { replyTo: msg.id });
  const language = languageFor(serverId);
  const requestedRoleName = (msg.args || '').trim() || serverSettings[serverId]?.authenticatedRoleName || 'Authenticated';
  if (requestedRoleName.length > 100) return msg.reply('Role names must be 100 characters or fewer.', { replyTo: msg.id });

  let channel;
  try {
    channel = await bot.createChannel(serverId, 'antialt-verify', { kind: 'text' });
  } catch (error) {
    const reason = error.status === 403 ? language.missingManageChannels : language.channelCreateFailed(error.message);
    try { await msg.reply(reason, { replyTo: msg.id }); }
    catch (replyError) { console.error('[AntiAlt] setup failure response could not be sent:', replyError.message); }
    return;
  }

  let matchingRole = null;
  try {
    matchingRole = (await bot.roles(serverId)).find((role) => role.name?.toLowerCase() === requestedRoleName.toLowerCase()) || null;
  } catch (error) {
    console.error('[AntiAlt] could not inspect server roles:', error.message);
  }
  serverSettings[serverId] = {
    ...serverSettings[serverId],
    authenticatedRoleName: requestedRoleName,
    authenticatedRoleId: matchingRole?.id || null,
  };
  try { saveSettings(); }
  catch (error) {
    console.error('[AntiAlt] could not save authenticated role setting:', error.message);
    try { await msg.reply(language.roleSetupFailed, { replyTo: msg.id }); } catch { /* original reply may also be unavailable */ }
    return;
  }

  const embed = new Embed()
    .title(language.verifyTitle)
    .description(language.verifyDescription)
    .color('blue');
  try {
    await bot.send(channel.id, '', {
      embeds: [embed],
      components: [new Row(Button.success(language.verifyButton, `antialt:verify:${serverId}`))],
    });
  } catch (error) {
    try { await msg.reply(language.channelPostFailed(channel.id), { replyTo: msg.id }); }
    catch (replyError) { console.error('[AntiAlt] could not report channel message failure:', replyError.message); }
    console.error('[AntiAlt] could not post verification panel:', error.message);
    return;
  }
  await msg.reply(language.setupDone(channel.id, requestedRoleName, !!matchingRole), { replyTo: msg.id });
});

bot.onButton(/^antialt:verify:/, async (interaction) => {
  const serverId = interaction.custom_id.slice('antialt:verify:'.length);
  const language = languageFor(serverId);
  if (!interaction.user_id || !serverId) return interaction.ephemeral(language.verificationUnmatched);
  const serverRecords = verifiedUsers[serverId] || {};
  const staleMismatches = Object.entries(serverRecords).filter(([accountId, record]) =>
    !record.manual && String(accountId) !== String(interaction.user_id) && String(record.requested_by_user_id) === String(interaction.user_id));
  if (staleMismatches.length) {
    for (const [accountId] of staleMismatches) delete serverRecords[accountId];
    try { saveVerifications(); }
    catch (error) {
      for (const [accountId, record] of staleMismatches) serverRecords[accountId] = record;
      console.error('[AntiAlt] could not remove legacy mismatched verification records:', error.message);
      return interaction.ephemeral(language.saveFailed);
    }
    try { await removeAuthenticatedRole(serverId, interaction.user_id); }
    catch (error) {
      console.error('[AntiAlt] could not remove role from legacy mismatched verification:', error.message);
      return interaction.ephemeral(language.roleRemoveFailed);
    }
  }
  const remainingRecords = Object.entries(serverRecords).filter(([, record]) => String(record.requested_by_user_id) === String(interaction.user_id));
  const existingVerification = remainingRecords.find(([accountId, record]) => record.manual || String(accountId) === String(interaction.user_id))?.[1]
    || remainingRecords[0]?.[1];
  if (existingVerification && !existingVerification.manual && (existingVerification.fingerprint_version !== 2 || existingVerification.privacy_version !== '4')) {
    const linkToken = randomBytes(32).toString('hex');
    const authcode = randomBytes(32).toString('hex');
    const accountId = Object.keys(verifiedUsers[serverId]).find((id) => verifiedUsers[serverId][id] === existingVerification);
    pendingAuthStart.set(linkToken, {
      authcode, serverId, userId: interaction.user_id,
      username: interaction.username || existingVerification.username || 'unknown',
      language: serverSettings[serverId]?.language || 'en',
      deviceRebind: true, existingAccountId: accountId,
      expiresAt: Date.now() + 15 * 60 * 1000,
    });
    const localLink = new URL('/authenticate', callbackUrl);
    localLink.searchParams.set('token', linkToken);
    localLink.searchParams.set('authcode', authcode);
    localLink.searchParams.set('serverid', serverId);
    return interaction.ephemeral(language.deviceRefresh(localLink.toString()));
  }
  if (existingVerification) {
    await interaction.ack();
    try {
      const roleResult = await ensureAuthenticatedRole(serverId, interaction.user_id);
      if (roleResult.status === 'added') return interaction.ephemeral(language.alreadyVerifiedRoleAdded());
      if (roleResult.status === 'missing') return interaction.ephemeral(language.authenticatedRoleMissing(roleResult.roleName));
    } catch (error) {
      console.error('[AntiAlt] already-verified user role restoration failed:', error.message);
      return interaction.ephemeral(`${language.alreadyVerified()} ${language.roleAssignFailed}`);
    }
    return interaction.ephemeral(language.alreadyVerified());
  }
  if (!OAUTH_CLIENT_ID || !process.env.AUTH_TOKEN_WEBSITE_CLIENT_SECRET || !process.env.AUTH_TOKEN_WEBSITE_CALLBACK) {
    return interaction.ephemeral(language.oauthNotConfigured);
  }

  const linkToken = randomBytes(32).toString('hex');
  const authcode = randomBytes(32).toString('hex');
  pendingAuthStart.set(linkToken, {
    authcode,
    serverId,
    userId: interaction.user_id,
    username: interaction.username || 'unknown',
    language: serverSettings[serverId]?.language || 'en',
    expiresAt: Date.now() + 15 * 60 * 1000,
  });
  const localLink = new URL('/authenticate', callbackUrl);
  localLink.searchParams.set('token', linkToken);
  localLink.searchParams.set('authcode', authcode);
  localLink.searchParams.set('serverid', serverId);
  return interaction.ephemeral(language.oauthStart(localLink.toString()));
});

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const readCookie = (header, name) => {
  const part = String(header || '').split(';').map((value) => value.trim()).find((value) => value.startsWith(`${name}=`));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : null;
};
const consentForm = (language, consentId) => `<p>${escapeHtml(language.consentQuestion)}</p><h2>${escapeHtml(language.termsTitle)}</h2><p>${escapeHtml(language.termsText)}</p><h2>${escapeHtml(language.privacyTitle)}</h2><p>${escapeHtml(language.privacyText)}</p><form method="post" action="/consent"><input type="hidden" name="consent_id" value="${escapeHtml(consentId)}"><button name="decision" value="yes">${escapeHtml(language.consentYes)}</button> <button name="decision" value="no">${escapeHtml(language.consentNo)}</button></form>`;
const htmlPage = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${escapeHtml(title)}</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#e8edf5;background:#0b1020}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(ellipse at top,#182442 0,#0b1020 58%)}main{width:min(100%,680px);padding:clamp(24px,5vw,42px);border:1px solid #28344b;border-radius:18px;background:#111827;box-shadow:0 24px 80px #0006}h1{margin:0 0 20px;font-size:clamp(1.55rem,4vw,2rem);letter-spacing:-.03em}h2{margin:24px 0 8px;font-size:1rem;color:#c8d4e8}p{margin:0 0 14px;color:#aebbd0;line-height:1.65}form{display:flex;flex-wrap:wrap;gap:12px;margin-top:28px}button{min-height:44px;padding:0 18px;border:1px solid #3a4963;border-radius:10px;background:#202c40;color:#eef4ff;font:600 .95rem/1.2 system-ui,sans-serif;cursor:pointer}button:hover{background:#2b3b56}button[value="yes"]{border-color:#4d8b70;background:#226444}button[value="yes"]:hover{background:#2a7954}button:focus-visible{outline:3px solid #8ab4ff;outline-offset:2px}@media(prefers-reduced-motion:no-preference){button{transition:background .15s ease}}
</style></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;


function getConsentClientIp(req) {
  let address = req.socket.remoteAddress || '';
  if (process.env.ANTIALT_TRUST_PROXY === 'true') {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) address = forwarded.split(',')[0].trim();
  }
  address = address.trim().toLowerCase().replace(/^::ffff:/, '');
  if (!address || address === '::1' || address.startsWith('127.')) return null;
  return address;
}
function keyedIpHash(ip) {
  if (!ipHashKey) {
    try { ipHashKey = readFileSync(IP_HASH_KEY_FILE); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      mkdirSync(DATA_DIR, { recursive: true });
      ipHashKey = randomBytes(32);
      writeFileSync(IP_HASH_KEY_FILE, ipHashKey, { flag: 'wx', mode: 0o600 });
    }
  }
  return createHmac('sha256', ipHashKey).update(ip).digest('hex');
}

const callbackUrl = new URL(OAUTH_CALLBACK);
const isLocalHttpCallback = callbackUrl.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(callbackUrl.hostname);
const isPublicHttpsCallback = callbackUrl.protocol === 'https:' && !['localhost', '127.0.0.1'].includes(callbackUrl.hostname);
if ((!isLocalHttpCallback && !isPublicHttpsCallback) || !Number.isInteger(OAUTH_PORT) || OAUTH_PORT < 1 || OAUTH_PORT > 65535 || callbackUrl.pathname !== '/callback') {
  throw new Error('AUTH_TOKEN_WEBSITE_CALLBACK must be an HTTPS /callback URL or a localhost HTTP /callback URL.');
}

createServer(async (req, res) => {
  const requestUrl = new URL(req.url || '/', OAUTH_CALLBACK);
  const sendPage = (status, title, body, extraHeaders = {}) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', ...extraHeaders });
    res.end(htmlPage(title, body));
  };
  if (requestUrl.pathname === '/authenticate' && req.method === 'GET') {
    const linkToken = requestUrl.searchParams.get('token') || '';
    const authcode = requestUrl.searchParams.get('authcode') || '';
    const serverId = requestUrl.searchParams.get('serverid') || '';
    const pending = pendingAuthStart.get(linkToken);
    const supplied = Buffer.from(authcode);
    const expected = Buffer.from(pending?.authcode || randomBytes(32).toString('hex'));
    const codeMatches = supplied.length === expected.length && timingSafeEqual(supplied, expected);
    if (!pending || !codeMatches || pending.serverId !== serverId || pending.expiresAt < Date.now()) {
      pendingAuthStart.delete(linkToken);
      return sendPage(400, 'Verification link expired', '<p>This one-time link is invalid or expired. Return to Yapin’ and click Verify again.</p>');
    }
    pendingAuthStart.delete(linkToken);
    const existingDeviceCookie = readCookie(req.headers.cookie, 'antialt_device');
    const deviceCookie = existingDeviceCookie && /^[a-f0-9]{64}$/.test(existingDeviceCookie)
      ? existingDeviceCookie
      : randomBytes(32).toString('hex');
    const state = randomBytes(32).toString('hex');
    pendingOAuth.set(state, { ...pending, deviceCookie, expiresAt: Date.now() + 15 * 60 * 1000 });
    const authorize = new URL('https://www.yapin.gg/oauth/authorize');
    authorize.searchParams.set('client_id', OAUTH_CLIENT_ID);
    authorize.searchParams.set('redirect_uri', OAUTH_CALLBACK);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('scope', 'identify');
    authorize.searchParams.set('state', state);
    const headers = { location: authorize.toString(), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' };
    res.writeHead(302, headers);
    return res.end();
  }
  if (requestUrl.pathname === '/callback' && req.method === 'GET') {
    const state = requestUrl.searchParams.get('state') || '';
    const pending = pendingOAuth.get(state);
    const code = requestUrl.searchParams.get('code');
    if (!pending || pending.expiresAt < Date.now() || !code || requestUrl.searchParams.has('error')) {
      pendingOAuth.delete(state);
      return sendPage(400, 'Sign-in expired', '<p>Return to Yapin’ and click Verify again.</p>');
    }
    pendingOAuth.delete(state);
    const language = LANGUAGES[pending.language] || LANGUAGES.en;
    let identity;
    try {
      const tokenResponse = await fetch(OAUTH_TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: OAUTH_CALLBACK,
          client_id: OAUTH_CLIENT_ID,
          client_secret: process.env.AUTH_TOKEN_WEBSITE_CLIENT_SECRET,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const tokenBody = await tokenResponse.json();
      if (!tokenResponse.ok || typeof tokenBody.access_token !== 'string') throw new Error(`Token exchange failed (${tokenResponse.status})`);
      const identityResponse = await fetch(OAUTH_IDENTITY_ENDPOINT, {
        headers: { authorization: `Bearer ${tokenBody.access_token}`, accept: 'application/json' },
        signal: AbortSignal.timeout(15000),
      });
      const profile = await identityResponse.json();
      if (!identityResponse.ok || !profile.id) throw new Error(`Identity lookup failed (${identityResponse.status})`);
      identity = { id: String(profile.id), username: profile.username || profile.display_name || pending.username };
    } catch (error) {
      console.error('[AntiAlt] OAuth identity lookup failed:', error.message);
      return sendPage(502, 'Sign-in failed', `<p>${escapeHtml(language.oauthFailure)}</p>`);
    }
    if (identity.id !== String(pending.userId)) {
      console.warn(`[AntiAlt] rejected OAuth identity mismatch for server ${pending.serverId}; the verification link belongs to user ${pending.userId}`);
      return sendPage(403, 'Account mismatch', `<p>${escapeHtml(language.oauthAccountMismatch)}</p>`);
    }
    const consentId = randomBytes(24).toString('base64url');
    pendingConsent.set(consentId, { ...pending, identity, expiresAt: Date.now() + 5 * 60 * 1000 });
    return sendPage(200, 'AntiAlt verification', consentForm(language, consentId));
  }
  if (requestUrl.pathname === '/consent' && req.method === 'POST') {
    let raw = '';
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > 8192) return sendPage(413, 'Request too large', '<p>Request rejected.</p>');
    }
    const form = new URLSearchParams(raw);
    const consentId = form.get('consent_id') || '';
    const pending = pendingConsent.get(consentId);
    if (!pending || pending.expiresAt < Date.now()) {
      pendingConsent.delete(consentId);
      return sendPage(400, 'Verification expired', '<p>Return to Yapin’ and click Verify again.</p>');
    }
    pendingConsent.delete(consentId);
    const language = LANGUAGES[pending.language] || LANGUAGES.en;
    if (form.get('decision') !== 'yes') return sendPage(200, 'Consent declined', `<p>${escapeHtml(language.consentDeclined)}</p>`);

    const consentIp = getConsentClientIp(req);
    if (consentIp && vpnRanges.length && isListedVpnIp(consentIp)) {
      return sendPage(403, 'VPN verification blocked', `<p>${escapeHtml(language.vpnBlocked)}</p>`);
    }

    const identity = pending.identity;
    const accountId = identity.id;
    const username = identity.username;
      const serverRecords = verifiedUsers[pending.serverId] ||= {};
      const deviceHash = createHash('sha256').update(pending.deviceCookie).digest('hex');
      const ipHash = consentIp ? keyedIpHash(consentIp) : null;
      const duplicateMatch = Object.entries(serverRecords).find(([savedAccountId, record]) => savedAccountId !== accountId && record.fingerprint_version === 2 && ((record.device_hash === deviceHash) || (ipHash && record.ip_hash === ipHash)));
      if (duplicateMatch) {
        if (pending.deviceRebind && serverRecords[accountId]?.requested_by_user_id === pending.userId) {
          delete serverRecords[accountId];
          try { saveVerifications(); } catch (error) { console.error('[AntiAlt] could not revoke duplicate verification record:', error.message); }
          const roleId = serverSettings[pending.serverId]?.authenticatedRoleId;
          if (roleId) {
            try { await bot.removeRole(pending.serverId, pending.userId, roleId); }
            catch (error) { console.error('[AntiAlt] could not remove role from duplicate account:', error.message); }
          }
        }
        return sendPage(409, language.duplicateBrowserTitle, `<p>${escapeHtml(language.duplicateBrowser)}</p>`);
      }
      const existing = serverRecords[accountId];
      if (existing && !(pending.deviceRebind && existing.requested_by_user_id === pending.userId)) {
        return sendPage(409, 'Already verified', `<p>This account is already verified in this server as <strong>${escapeHtml(existing.username || username)}</strong>.</p>`);
      }
      serverRecords[accountId] = {
        ...existing,
        username,
        requested_by_user_id: pending.userId,
        device_hash: deviceHash,
        ip_hash: ipHash || existing?.ip_hash || null,
        fingerprint_version: 2,
        consented_at: new Date().toISOString(),
        verified_at: new Date().toISOString(),
        terms_version: '4',
        privacy_version: '4',
      };
      try { saveVerifications(); }
      catch (error) { delete serverRecords[accountId]; throw error; }
    const languageForPending = LANGUAGES[pending.language] || LANGUAGES.en;
    let roleWarning = '';
    try {
      const roleResult = await ensureAuthenticatedRole(pending.serverId, pending.userId);
      if (roleResult.status === 'missing') roleWarning = `<p>${escapeHtml(languageForPending.authenticatedRoleMissing(roleResult.roleName))}</p>`;
    } catch (error) {
      console.error('[AntiAlt] verified account but role assignment failed:', error.message);
      roleWarning = `<p>${escapeHtml(languageForPending.roleAssignFailed)}</p>`;
    }
    const deviceCookieHeader = `antialt_device=${pending.deviceCookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000`;
    return sendPage(200, 'Verified', `<p>${escapeHtml(languageForPending.oauthComplete)}</p>${roleWarning}`, { 'set-cookie': deviceCookieHeader });
  }
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('Not found');
}).listen(OAUTH_PORT, OAUTH_BIND_HOST, () => {
  console.log(`[AntiAlt] OAuth callback listening on ${OAUTH_BIND_HOST}:${OAUTH_PORT} for ${OAUTH_CALLBACK}`);
});

setInterval(() => {
  const now = Date.now();
  for (const [token, pending] of pendingAuthStart) if (pending.expiresAt <= now) pendingAuthStart.delete(token);
  for (const [state, pending] of pendingOAuth) if (pending.expiresAt <= now) pendingOAuth.delete(state);
  for (const [id, pending] of pendingConsent) if (pending.expiresAt <= now) pendingConsent.delete(id);
}, 60_000).unref();

bot.on('ready', async () => {
  try { await bot.setProfile({ displayName: 'AntiAlt' }); }
  catch (error) { console.error('[AntiAlt] could not update bot display name:', error.message); }
  try {
    const servers = await bot.servers();
    await bot.setStatus('online', `Protecting ${servers.length} Servers`);
  } catch (error) {
    console.error('[AntiAlt] could not update server-count status:', error.message);
  }
});

bot.start().catch((error) => {
  console.error('[AntiAlt] could not start:', error.message);
  process.exit(1);
});

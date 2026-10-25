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
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/airvpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/ivpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/mullvad.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/nordvpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/ovpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/pia.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/protonvpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/riseupvpn.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/surfshark.txt',
  'https://raw.githubusercontent.com/Joe12387/open-source-vpn-ip-lists/master/windscribe.txt',
  'https://raw.githubusercontent.com/tn3w/ProtonVPN-IPs/master/protonvpn_ip_ranges.txt',
];
const VPN_LIST_REFRESH_MS = 12 * 60 * 60 * 1000;
const TERMS_VERSION = '6';
const PRIVACY_VERSION = '7';
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
    verifyDescription: 'Click Verify to authenticate your Yapin’ account. After sign-in, you must accept the Terms and Privacy Notice and the disclosed browser fingerprint check. AntiAlt stores a random browser-cookie hash, a keyed IP hash, and a keyed hash of browser/system details. It does not store raw IPs or hardware serial numbers.',
    termsTitle: 'Terms of Service',
    termsText: 'By continuing, you agree to use AntiAlt only for server safety and to provide accurate account information. Verification is limited to one Yapin’ account per server, IP address, browser profile, and the disclosed browser fingerprint. AntiAlt also checks the callback IP against a public list of known VPN networks; a match blocks verification. People sharing an IP address, VPN, or network may be grouped and blocked together. The fingerprint uses browser and system details; it is not a hardware serial number or guaranteed physical-device ID. If you choose to remember your decision, a signed browser cookie will remember this account’s acceptance while the cookie remains valid and the policy version is current. Browsers may expire or clear cookies. Server administrators control this bot and its verification settings.',
    privacyTitle: 'Privacy Notice',
    privacyText: 'After you accept both checkboxes, AntiAlt stores your Yapin’ account ID and username, server ID, consent and verification timestamps, a SHA-256 hash of a random first-party browser cookie, a keyed HMAC-SHA-256 hash of your IP, and a server-keyed HMAC hash of a browser fingerprint. JavaScript calculates the fingerprint locally from browser version/user agent, platform, language, time zone, screen size and color depth, pixel ratio, and available CPU-thread and device-memory values. Only its SHA-256 digest is sent; raw feature values are not stored. The fingerprint can change or be shared and is not a hardware serial number or guaranteed physical-device ID. Raw IP addresses are not stored. The IP is checked locally against public VPN server lists from X4BNet, the Open Source VPN IP Lists project, and the daily ProtonVPN-IPs project; it is not sent to a separate IP lookup service. The ProtonVPN sources do not distinguish free from paid servers. One source expands Proton server IPs to /24 IPv4 ranges to catch exit traffic that uses nearby addresses; this can also block non-VPN addresses in those ranges. If you select “Remember my decision,” a signed HttpOnly cookie stores hashes of this account, browser, and fingerprint plus the accepted policy versions. It suppresses future consent prompts for this account on this browser while the cookie remains valid and the policy version is current; browsers may expire or clear cookies. Shared IPs, VPNs, or devices can cause accounts to be grouped. The bot operator can access these records. Ask the server administrators to request deletion.',
    consentQuestion: 'Do you accept our Terms of Service & Privacy Policy?',
    consentCheckboxLabel: 'I have read and agree to the Terms of Service and Privacy Notice.',
    deviceConsentCheckboxLabel: 'I agree to AntiAlt creating a browser fingerprint from the disclosed browser and system details.',
    deviceConsentRequiredError: 'Check the browser fingerprint agreement box to continue.',
    rememberConsentLabel: 'Remember my decision on this browser for this Yapin’ account.',
    consentRequiredError: 'Check the agreement box to continue.',
    fingerprintUnavailable: 'AntiAlt could not create the required browser fingerprint. Enable JavaScript and try again.',
    consentYes: 'Yes, I accept',
    consentNo: 'No, I do not accept',
    consentDeclined: 'You declined. No verification data was saved.',
    oauthComplete: 'Sign-in and consent are complete. You can return to the server.',
    oauthSetupMissing: 'OAuth sign-in needs token and identity endpoint URLs configured by the bot operator.',
    oauthStart: (url) => `Your secure sign-in link (valid for 15 minutes): ${url}`,
    deviceRefresh: (url) => `You're already verified. Accept the updated Privacy Notice here to activate browser duplicate checks: ${url}`,
    duplicateBrowserTitle: 'Alt Account Attempt Blocked',
    duplicateBrowser: 'This account matched a previous verification from this server by IP hash, browser cookie, or browser fingerprint. It was not verified, and its verification role was removed if it had one. AntiAlt stores hashes, not the raw IP or a hardware serial number. Shared networks and similar devices can cause false positives; contact a server administrator if you think this is a mistake.',
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
    ipSecurityUnavailable: 'Verification is temporarily unavailable because AntiAlt could not read a valid visitor IP. The server administrator may need to enable trusted proxy IP forwarding.',
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
    verifyDescription: 'Klicke auf Verifizieren, um deinen Yapin’-Account anzumelden. Nach der Anmeldung musst du den Bedingungen, dem Datenschutzhinweis und dem offengelegten Browser-Fingerprint zustimmen. AntiAlt speichert einen Browser-Cookie-Hash, einen keyed IP-Hash und einen keyed Hash von Browser-/Systemmerkmalen. Rohe IP-Adressen und Hardware-Seriennummern werden nicht gespeichert.',
    termsTitle: 'Nutzungsbedingungen',
    termsText: 'Wenn du fortfährst, stimmst du zu, AntiAlt nur zur Sicherheit des Servers zu nutzen und korrekte Account-Informationen anzugeben. Die Verifizierung ist auf einen Yapin’-Account pro Server, IP-Adresse, Browserprofil und den offengelegten Browser-Fingerprint begrenzt. Zusätzlich vergleicht AntiAlt die Callback-IP mit einer öffentlichen Liste bekannter VPN-Netzwerke; ein Treffer blockiert die Verifizierung. Personen mit gemeinsamer IP, VPN oder gemeinsamem Netzwerk können zusammengefasst und blockiert werden. Der Fingerprint nutzt Browser- und Systemmerkmale, ist aber keine Hardware-Seriennummer oder garantierte physische Geräte-ID. Wenn du deine Entscheidung speichern lässt, merkt sich ein signiertes Browser-Cookie die Zustimmung dieses Accounts, solange das Cookie gültig und die Richtlinien-Version aktuell ist. Browser können Cookies löschen oder vorzeitig ablaufen lassen. Die Server-Admins verwalten diesen Bot und seine Einstellungen.',
    privacyTitle: 'Datenschutzhinweis',
    privacyText: 'Nach beiden Zustimmungen speichert AntiAlt deine Yapin’-Account-ID und deinen Nutzernamen, Server-ID, Zustimmungs- und Verifizierungszeitpunkte, einen SHA-256-Hash eines zufälligen Erstanbieter-Browser-Cookies, einen keyed HMAC-SHA-256-Hash der IP und einen server-keyed HMAC-Hash des Browser-Fingerprints. JavaScript berechnet den Fingerprint lokal aus Browser-Version/User-Agent, Plattform, Sprache, Zeitzone, Bildschirmgröße und Farbtiefe, Pixeldichte sowie verfügbaren CPU-Thread- und Gerätespeicherwerten. Nur der SHA-256-Digest wird gesendet; die Rohmerkmale werden nicht gespeichert. Der Fingerprint kann sich ändern oder geteilt werden und ist keine Hardware-Seriennummer oder garantierte Geräte-ID. Rohe IP-Adressen werden nicht gespeichert. Die IP wird lokal mit öffentlichen VPN-Serverlisten von X4BNet, dem Projekt Open Source VPN IP Lists und dem täglich aktualisierten Projekt ProtonVPN-IPs verglichen; sie wird nicht an einen separaten IP-Abfragedienst gesendet. Die ProtonVPN-Quellen unterscheiden nicht zwischen kostenlosen und kostenpflichtigen Servern. Eine Quelle erweitert Proton-Server-IP-Adressen auf IPv4-/24-Netze, um Exit-Traffic über benachbarte Adressen zu erfassen; dadurch können auch Nicht-VPN-Adressen in diesen Netzen blockiert werden. Wenn du „Meine Entscheidung speichern“ aktivierst, enthält ein signiertes HttpOnly-Cookie Hashes dieses Yapin’-Accounts, des Browsers und des Fingerprints sowie die akzeptierten Richtlinien-Versionen. Es unterdrückt weitere Zustimmungsfragen für diesen Account in diesem Browser, solange das Cookie gültig und die Richtlinien-Version aktuell ist; Browser können Cookies löschen oder vorzeitig ablaufen lassen. Gemeinsame IPs, VPNs oder Geräte können Accounts zusammenfassen. Der Bot-Betreiber kann auf diese Daten zugreifen. Bitte die Server-Admins um Löschung.',
    consentQuestion: 'Akzeptierst du unsere Nutzungsbedingungen und Datenschutzerklärung?',
    consentCheckboxLabel: 'Ich habe die Nutzungsbedingungen und den Datenschutzhinweis gelesen und stimme ihnen zu.',
    deviceConsentCheckboxLabel: 'Ich stimme zu, dass AntiAlt aus den offengelegten Browser- und Systemdaten einen Browser-Fingerprint erstellt.',
    deviceConsentRequiredError: 'Aktiviere das Zustimmungsfeld für den Browser-Fingerprint, um fortzufahren.',
    rememberConsentLabel: 'Meine Entscheidung in diesem Browser für diesen Yapin’-Account speichern.',
    consentRequiredError: 'Aktiviere das Zustimmungsfeld, um fortzufahren.',
    fingerprintUnavailable: 'AntiAlt konnte den erforderlichen Browser-Fingerprint nicht erstellen. Aktiviere JavaScript und versuche es erneut.',
    consentYes: 'Ja, ich stimme zu',
    consentNo: 'Nein, ich stimme nicht zu',
    consentDeclined: 'Du hast abgelehnt. Es wurden keine Verifizierungsdaten gespeichert.',
    oauthComplete: 'Anmeldung und Zustimmung sind abgeschlossen. Du kannst zum Server zurückkehren.',
    oauthSetupMissing: 'Für OAuth müssen Token- und Identitäts-Endpunkt-URLs vom Bot-Betreiber eingerichtet werden.',
    oauthStart: (url) => `Dein sicherer Anmeldelink (15 Minuten gültig): ${url}`,
    deviceRefresh: (url) => `Du bist bereits verifiziert. Stimme hier dem aktualisierten Datenschutzhinweis zu, um Browser-Duplikatprüfungen zu aktivieren: ${url}`,
    duplicateBrowserTitle: 'Alt-Account-Versuch blockiert',
    duplicateBrowser: 'Dieser Account stimmt beim IP-Hash, Browser-Cookie oder Browser-Fingerprint mit einer früheren Verifizierung in diesem Server überein. Er wurde nicht verifiziert; eine vorhandene Verifizierungsrolle wurde nach Möglichkeit entfernt. AntiAlt speichert Hashes, nicht die rohe IP oder eine Hardware-Seriennummer. Gemeinsame Netzwerke und ähnliche Geräte können Fehlalarme verursachen; wende dich bei einem vermuteten Fehler an einen Server-Admin.',
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
    ipSecurityUnavailable: 'Die Verifizierung ist vorübergehend nicht verfügbar, weil AntiAlt keine gültige Besucher-IP erhalten hat. Ein Server-Admin muss möglicherweise die vertrauenswürdige IP-Weitergabe des Proxys aktivieren.',
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
    verifyDescription: 'Pulsa Verificar para autenticar tu cuenta de Yapin’. Después del inicio de sesión, debes aceptar los términos, el aviso de privacidad y la comprobación de huella descrita. AntiAlt guarda un hash de cookie aleatoria, un hash de IP con clave y un hash con clave de los datos del navegador y sistema. No guarda IPs sin procesar ni números de serie de hardware.',
    termsTitle: 'Términos de servicio',
    termsText: 'Al continuar, aceptas usar AntiAlt solo para la seguridad del servidor y proporcionar información de cuenta correcta. Se limita a una cuenta de Yapin’ por servidor, dirección IP, perfil del navegador y la huella descrita. AntiAlt también compara la IP de retorno con una lista pública de redes VPN conocidas; una coincidencia bloquea la verificación. Las personas que compartan IP, VPN o red pueden agruparse y bloquearse juntas. La huella usa datos del navegador y sistema, pero no es un número de serie ni una identificación física garantizada. Si eliges recordar tu decisión, una cookie firmada recordará la aceptación de esta cuenta mientras la cookie siga válida y la versión de la política esté vigente. El navegador puede borrar o caducar las cookies. Los administradores controlan este bot y su configuración.',
    privacyTitle: 'Aviso de privacidad',
    privacyText: 'Tras aceptar ambas casillas, AntiAlt guarda tu ID de Yapin’, nombre de usuario, ID del servidor, fechas de consentimiento/verificación, un hash SHA-256 de una cookie aleatoria, un hash HMAC-SHA-256 con clave de la IP y un hash HMAC con clave de la huella del navegador. JavaScript calcula localmente la huella a partir de la versión/User-Agent, plataforma, idioma, zona horaria, tamaño y profundidad de color de pantalla, densidad de píxeles y valores disponibles de hilos de CPU y memoria. Solo se envía el digest SHA-256; no se guardan los datos originales. La huella puede cambiar o compartirse y no es un número de serie ni una identificación física garantizada. No se guardan IPs sin procesar. La IP se compara localmente con listas públicas de servidores VPN de X4BNet, del proyecto Open Source VPN IP Lists y del proyecto ProtonVPN-IPs, actualizado a diario; no se envía a otro servicio de consulta. Las fuentes de ProtonVPN no diferencian entre servidores gratuitos y de pago. Una fuente amplía las IPs de servidores Proton a rangos IPv4 /24 para detectar tráfico de salida mediante direcciones cercanas; esto también puede bloquear direcciones que no sean VPN dentro de esos rangos. Si seleccionas “Recordar mi decisión”, una cookie firmada HttpOnly guarda hashes de esta cuenta de Yapin’, del navegador y de la huella, junto con las versiones aceptadas. No volverá a aparecer la pregunta para esta cuenta en este navegador mientras la cookie siga válida y la versión de la política esté vigente; el navegador puede borrar o caducar las cookies. Las IPs, VPNs o dispositivos compartidos pueden agrupar cuentas. El operador del bot puede acceder a estos datos. Solicita su eliminación a los administradores del servidor.',
    consentQuestion: '¿Aceptas nuestros Términos de servicio y Política de privacidad?',
    consentCheckboxLabel: 'He leído y acepto los Términos de servicio y el Aviso de privacidad.',
    deviceConsentCheckboxLabel: 'Acepto que AntiAlt cree una huella del navegador con los datos del navegador y sistema descritos.',
    deviceConsentRequiredError: 'Marca la casilla de consentimiento para la huella del navegador.',
    rememberConsentLabel: 'Recordar mi decisión en este navegador para esta cuenta de Yapin’.',
    consentRequiredError: 'Marca la casilla de aceptación para continuar.',
    fingerprintUnavailable: 'AntiAlt no pudo crear la huella requerida. Activa JavaScript e inténtalo de nuevo.',
    consentYes: 'Sí, acepto',
    consentNo: 'No, no acepto',
    consentDeclined: 'Has rechazado. No se guardaron datos de verificación.',
    oauthComplete: 'El inicio de sesión y el consentimiento se completaron. Puedes volver al servidor.',
    oauthSetupMissing: 'El operador del bot debe configurar las URL de token e identidad de OAuth.',
    oauthStart: (url) => `Tu enlace seguro de inicio de sesión (válido durante 15 minutos): ${url}`,
    deviceRefresh: (url) => `Ya estás verificado. Acepta aquí el Aviso de privacidad actualizado para activar la detección de duplicados del navegador: ${url}`,
    duplicateBrowserTitle: 'Intento de cuenta alternativa bloqueado',
    duplicateBrowser: 'Esta cuenta coincide con una verificación anterior por hash de IP, cookie o huella del navegador. No fue verificada y se quitó su rol si lo tenía. AntiAlt guarda hashes, no la IP sin procesar ni un número de serie de hardware. Las redes compartidas y dispositivos similares pueden causar falsos positivos; contacta con un administrador si crees que es un error.',
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
    ipSecurityUnavailable: 'La verificación no está disponible porque AntiAlt no recibió una IP válida del visitante. Es posible que un administrador deba activar el reenvío de IP del proxy de confianza.',
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
    const results = await Promise.allSettled(VPN_LIST_URLS.map(async (url) => {
      const response = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error(`${response.status} ${url}`);
      return response.text();
    }));
    const contents = results.filter((result) => result.status === 'fulfilled').map((result) => result.value);
    const failures = results.filter((result) => result.status === 'rejected');
    if (failures.length) console.error(`[AntiAlt] ${failures.length} VPN list source(s) failed; continuing with available sources`);
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
  if (existingVerification && !existingVerification.manual && (existingVerification.fingerprint_version !== 2 || existingVerification.terms_version !== TERMS_VERSION || existingVerification.privacy_version !== PRIVACY_VERSION)) {
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
  return part ? part.slice(name.length + 1) : null;
};
const consentForm = (language, consentId, errorMessage = '') => `${errorMessage ? `<p role="alert">${escapeHtml(errorMessage)}</p>` : ''}<p>${escapeHtml(language.consentQuestion)}</p><nav class="policy-links"><button type="button" data-policy-open="terms">${escapeHtml(language.termsTitle)}</button><button type="button" data-policy-open="privacy">${escapeHtml(language.privacyTitle)}</button></nav><form method="post" action="/consent"><input type="hidden" name="consent_id" value="${escapeHtml(consentId)}"><input type="hidden" name="device_fingerprint" value=""><label class="check-label"><input type="checkbox" name="agree" value="yes" required><span class="checkbox-mark" aria-hidden="true"></span><span>${escapeHtml(language.consentCheckboxLabel)}</span></label><label class="check-label"><input type="checkbox" name="device_consent" value="yes" required><span class="checkbox-mark" aria-hidden="true"></span><span>${escapeHtml(language.deviceConsentCheckboxLabel)}</span></label><label class="check-label"><input type="checkbox" name="remember" value="yes"><span class="checkbox-mark" aria-hidden="true"></span><span>${escapeHtml(language.rememberConsentLabel)}</span></label><div><button name="decision" value="yes">${escapeHtml(language.consentYes)}</button> <button name="decision" value="no" formnovalidate>${escapeHtml(language.consentNo)}</button></div></form><dialog id="policy-dialog" aria-label="${escapeHtml(language.termsTitle)} / ${escapeHtml(language.privacyTitle)}"><button class="dialog-close" type="button" aria-label="Close">×</button><article data-policy-content="terms"><h2>${escapeHtml(language.termsTitle)}</h2><p>${escapeHtml(language.termsText)}</p></article><article data-policy-content="privacy"><h2>${escapeHtml(language.privacyTitle)}</h2><p>${escapeHtml(language.privacyText)}</p></article></dialog><script src="/consent.js" defer></script>`;
const htmlPage = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${escapeHtml(title)}</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#e8edf5;background:#0b1020}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(ellipse at top,#182442 0,#0b1020 58%)}main{width:min(100%,680px);padding:clamp(24px,5vw,42px);border:1px solid #28344b;border-radius:18px;background:#111827;box-shadow:0 24px 80px #0006}h1{margin:0 0 20px;font-size:clamp(1.55rem,4vw,2rem);letter-spacing:-.03em}h2{margin:24px 0 8px;font-size:1rem;color:#c8d4e8}p{margin:0 0 14px;color:#aebbd0;line-height:1.65}.policy-links{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0 8px}.policy-links button{display:inline-flex;align-items:center;min-height:44px;padding:0 14px;border:1px solid #3a4963;border-radius:10px;background:#202c40;color:#9cc4ff;font-weight:600;text-decoration:none}.policy-links button:hover{background:#2b3b56;color:#c1d8ff}form{display:flex;flex-direction:column;align-items:flex-start;gap:14px;margin-top:28px}.check-label{position:relative;display:flex;align-items:flex-start;gap:10px;color:#c6d0df;line-height:1.5;cursor:pointer}.check-label input{position:absolute;width:22px;height:22px;margin:0;opacity:0;cursor:pointer}.checkbox-mark{display:grid;place-items:center;width:20px;height:20px;margin:1px 0 0;flex:none;border:1px solid #52627a;border-radius:6px;background:#0d1524;transition:background .15s ease,border-color .15s ease,box-shadow .15s ease}.checkbox-mark::after{content:"";width:9px;height:5px;border:solid #fff;border-width:0 0 2px 2px;transform:rotate(-45deg) translate(1px,-1px);opacity:0}.check-label input:checked+.checkbox-mark{border-color:#58b987;background:#258253}.check-label input:checked+.checkbox-mark::after{opacity:1}.check-label input:focus-visible+.checkbox-mark{outline:3px solid #8ab4ff;outline-offset:3px}.check-label:hover .checkbox-mark{border-color:#79a9ff}button{min-height:44px;padding:0 18px;border:1px solid #3a4963;border-radius:10px;background:#202c40;color:#eef4ff;font:600 .95rem/1.2 system-ui,sans-serif;cursor:pointer}button:hover{background:#2b3b56}button[value="yes"]{border-color:#4d8b70;background:#226444}button[value="yes"]:hover{background:#2a7954}button:focus-visible{outline:3px solid #8ab4ff;outline-offset:2px}dialog#policy-dialog{position:fixed;inset:0;margin:auto;width:min(680px,calc(100% - 32px));max-height:min(80vh,720px);overflow:auto;padding:clamp(22px,5vw,36px);border:1px solid #3a4963;border-radius:18px;background:#111827;color:#e8edf5;box-shadow:0 24px 90px #000b}dialog#policy-dialog::backdrop{background:#050914c9;backdrop-filter:blur(5px)}dialog#policy-dialog h2{margin:0 48px 18px 0;font-size:1.35rem}dialog#policy-dialog p{white-space:normal;line-height:1.8}.dialog-close{position:sticky;float:right;top:0;width:40px;min-height:40px;padding:0;font-size:1.5rem;line-height:1}.dialog-close:hover{background:#3b2630}@media(prefers-reduced-motion:no-preference){button,.checkbox-mark{transition:background .15s ease,border-color .15s ease,box-shadow .15s ease}}
</style></head><body><main><h1>${escapeHtml(title)}</h1>${body}</main></body></html>`;


function getConsentClientIp(req) {
  let address = req.socket.remoteAddress || '';
  const proxyHeaderNames = ['cf-connecting-ip', 'true-client-ip', 'x-real-ip', 'x-forwarded-for'];
  const proxyHeaderName = proxyHeaderNames.find((name) => req.headers[name]);
  const socketIp = address.toLowerCase().replace(/^::ffff:/, '');
  const localTunnelProxy = ['127.0.0.1', '::1'].includes(socketIp) && !!proxyHeaderName;
  if (process.env.ANTIALT_TRUST_PROXY === 'true' || localTunnelProxy) {
    const forwarded = proxyHeaderName ? req.headers[proxyHeaderName] : null;
    if (typeof forwarded !== 'string' || !forwarded.trim()) return null;
    const forwardedAddresses = forwarded.split(',').map((part) => part.trim()).filter(Boolean);
    if (forwardedAddresses.length !== 1) return null;
    address = forwardedAddresses[0];
  }
  address = address.trim().toLowerCase();
  if (address.startsWith('[')) {
    const closingBracket = address.indexOf(']');
    if (closingBracket < 0) return null;
    address = address.slice(1, closingBracket);
  } else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(address)) {
    address = address.slice(0, address.lastIndexOf(':'));
  }
  address = address.replace(/^::ffff:/, '').replace(/%[a-z0-9_.-]+$/, '');
  const parsed = ipToBigInt(address);
  if (!parsed || parsed.value === 0n || (parsed.family === 4 && Number((parsed.value >> 24n) & 255n) === 127) || (parsed.family === 6 && parsed.value === 1n)) return null;
  return { address, hashInput: `${parsed.family}:${parsed.value.toString(16).padStart(parsed.family === 4 ? 8 : 32, '0')}` };
}
function getIpHashKey() {
  if (!ipHashKey) {
    try { ipHashKey = readFileSync(IP_HASH_KEY_FILE); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      mkdirSync(DATA_DIR, { recursive: true });
      const generatedKey = randomBytes(32);
      try {
        writeFileSync(IP_HASH_KEY_FILE, generatedKey, { flag: 'wx', mode: 0o600 });
        ipHashKey = generatedKey;
      } catch (writeError) {
        if (writeError.code !== 'EEXIST') throw writeError;
        ipHashKey = readFileSync(IP_HASH_KEY_FILE);
      }
    }
    if (ipHashKey.length !== 32) throw new Error('The IP hash key must contain exactly 32 bytes. Remove the invalid local key file to generate a new one.');
  }
  return ipHashKey;
}
function keyedIpHash(ip, serverId, legacy = false) {
  const key = getIpHashKey();
  return createHmac('sha256', key).update(legacy ? ip : `server:${serverId}\0ip:${ip}`).digest('hex');
}
function rememberedConsentToken(accountId, deviceCookie, acceptedAt, fingerprintHash) {
  const payload = Buffer.from(JSON.stringify({
    account: createHash('sha256').update(String(accountId)).digest('hex'),
    browser: createHash('sha256').update(String(deviceCookie)).digest('hex'),
    terms: TERMS_VERSION,
    privacy: PRIVACY_VERSION,
    acceptedAt,
    fingerprintHash,
  })).toString('base64url');
  const signature = createHmac('sha256', getIpHashKey()).update(`remember-consent\0${payload}`).digest('hex');
  return `${payload}.${signature}`;
}
function readRememberedConsent(cookieHeader, accountId, deviceCookie) {
  const token = readCookie(cookieHeader, 'antialt_consent');
  if (!token || token.length > 2048) return null;
  const [payload, suppliedSignature, extra] = token.split('.');
  if (!payload || !suppliedSignature || extra !== undefined || !/^[a-f0-9]{64}$/.test(suppliedSignature)) return null;
  let expectedSignature;
  try { expectedSignature = createHmac('sha256', getIpHashKey()).update(`remember-consent\0${payload}`).digest('hex'); }
  catch (error) {
    console.error('[AntiAlt] remembered consent validation failed:', error.message);
    return null;
  }
  const supplied = Buffer.from(suppliedSignature, 'hex');
  const expected = Buffer.from(expectedSignature, 'hex');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  let saved;
  try { saved = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); }
  catch { return null; }
  const accountHash = createHash('sha256').update(String(accountId)).digest('hex');
  const browserHash = createHash('sha256').update(String(deviceCookie)).digest('hex');
  if (saved.terms !== TERMS_VERSION || saved.privacy !== PRIVACY_VERSION || saved.account !== accountHash || saved.browser !== browserHash || !Number.isFinite(Date.parse(saved.acceptedAt))) return null;
  if (typeof saved.fingerprintHash !== 'string' || !/^[a-f0-9]{64}$/.test(saved.fingerprintHash)) return null;
  return { acceptedAt: saved.acceptedAt, fingerprintHash: saved.fingerprintHash };
}

const callbackUrl = new URL(OAUTH_CALLBACK);
const isLocalHttpCallback = callbackUrl.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(callbackUrl.hostname);
const isPublicHttpsCallback = callbackUrl.protocol === 'https:' && !['localhost', '127.0.0.1'].includes(callbackUrl.hostname);
if ((!isLocalHttpCallback && !isPublicHttpsCallback) || !Number.isInteger(OAUTH_PORT) || OAUTH_PORT < 1 || OAUTH_PORT > 65535 || callbackUrl.pathname !== '/callback') {
  throw new Error('AUTH_TOKEN_WEBSITE_CALLBACK must be an HTTPS /callback URL or a localhost HTTP /callback URL.');
}
if (isPublicHttpsCallback && process.env.ANTIALT_TRUST_PROXY !== 'true') {
  console.warn('[AntiAlt] public HTTPS callback detected but ANTIALT_TRUST_PROXY is not true; only recognized proxy headers arriving over loopback will be trusted. Set it to true only for a proxy you control when it connects from another address.');
}

createServer(async (req, res) => {
  const requestUrl = new URL(req.url || '/', OAUTH_CALLBACK);
  const sendPage = (status, title, body, extraHeaders = {}) => {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      ...extraHeaders,
    });
    res.end(htmlPage(title, body));
  };
  const completeVerification = async (pending, request, rememberDecision) => {
    const language = LANGUAGES[pending.language] || LANGUAGES.en;
    const consentIp = getConsentClientIp(request);
    if (!consentIp && isPublicHttpsCallback) {
      console.warn('[AntiAlt] refused verification because no valid client IP was received; check ANTIALT_TRUST_PROXY and the proxy client-IP header.');
      return sendPage(503, 'Connection check unavailable', `<p>${escapeHtml(language.ipSecurityUnavailable)}</p>`);
    }
    if (consentIp && vpnRanges.length && isListedVpnIp(consentIp.address)) {
      return sendPage(403, 'VPN verification blocked', `<p>${escapeHtml(language.vpnBlocked)}</p>`);
    }

    const identity = pending.identity;
    const accountId = identity.id;
    const username = identity.username;
    const serverRecords = verifiedUsers[pending.serverId] ||= {};
    const deviceHash = createHash('sha256').update(pending.deviceCookie).digest('hex');
    let ipHash = null;
    let legacyIpHash = null;
    let fingerprintHash = null;
    let rememberedToken = null;
    const acceptedAt = pending.rememberedConsentAt || new Date().toISOString();
    try {
      ipHash = consentIp ? keyedIpHash(consentIp.hashInput, pending.serverId) : null;
      legacyIpHash = consentIp ? keyedIpHash(consentIp.address, pending.serverId, true) : null;
      const fingerprintDigest = pending.deviceFingerprintDigest;
      if (fingerprintDigest) {
        if (!/^[a-f0-9]{64}$/.test(fingerprintDigest)) return sendPage(400, 'Fingerprint unavailable', `<p>${escapeHtml(language.fingerprintUnavailable)}</p>`);
        fingerprintHash = createHmac('sha256', getIpHashKey()).update(`server:${pending.serverId}\0browser-fingerprint:${fingerprintDigest}`).digest('hex');
      } else {
        fingerprintHash = pending.rememberedFingerprintHash || null;
      }
      if (!fingerprintHash) return sendPage(400, 'Fingerprint unavailable', `<p>${escapeHtml(language.fingerprintUnavailable)}</p>`);
      if (rememberDecision) rememberedToken = rememberedConsentToken(accountId, pending.deviceCookie, acceptedAt, fingerprintHash);
    } catch (error) {
      console.error('[AntiAlt] secure consent/IP processing failed:', error.message);
      return sendPage(503, 'Connection check unavailable', `<p>${escapeHtml(language.ipSecurityUnavailable)}</p>`);
    }

    const duplicateMatch = Object.entries(serverRecords).find(([savedAccountId, record]) => savedAccountId !== accountId && record.fingerprint_version === 2 && ((record.device_hash === deviceHash) || (record.fingerprint_hash === fingerprintHash) || (ipHash && record.ip_hash === ipHash) || (legacyIpHash && !record.ip_hash_version && record.ip_hash === legacyIpHash)));
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
      fingerprint_hash: fingerprintHash,
      ip_hash: ipHash || existing?.ip_hash || null,
      ip_hash_version: ipHash ? 2 : existing?.ip_hash_version || null,
      fingerprint_version: 2,
      consented_at: acceptedAt,
      verified_at: new Date().toISOString(),
      terms_version: TERMS_VERSION,
      privacy_version: PRIVACY_VERSION,
    };
    try { saveVerifications(); }
    catch (error) {
      if (existing) serverRecords[accountId] = existing;
      else delete serverRecords[accountId];
      if (!Object.keys(serverRecords).length) delete verifiedUsers[pending.serverId];
      console.error('[AntiAlt] could not save verification:', error.message);
      return sendPage(500, 'Verification could not be saved', `<p>${escapeHtml(language.saveFailed)}</p>`);
    }

    let roleWarning = '';
    try {
      const roleResult = await ensureAuthenticatedRole(pending.serverId, pending.userId);
      if (roleResult.status === 'missing') roleWarning = `<p>${escapeHtml(language.authenticatedRoleMissing(roleResult.roleName))}</p>`;
    } catch (error) {
      console.error('[AntiAlt] verified account but role assignment failed:', error.message);
      roleWarning = `<p>${escapeHtml(language.roleAssignFailed)}</p>`;
    }
    const secure = callbackUrl.protocol === 'https:' ? '; Secure' : '';
    const cookies = [`antialt_device=${pending.deviceCookie}; HttpOnly; SameSite=Lax; Path=/; Max-Age=31536000${secure}`];
    if (rememberedToken) cookies.push(`antialt_consent=${rememberedToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=315360000${secure}`);
    else if (rememberDecision === false) cookies.push(`antialt_consent=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
    return sendPage(200, 'Verified', `<p>${escapeHtml(language.oauthComplete)}</p>${roleWarning}`, { 'set-cookie': cookies });
  };
  if (requestUrl.pathname === '/consent.js' && req.method === 'GET') {
    const script = `document.addEventListener('DOMContentLoaded',()=>{const form=document.querySelector('form[action="/consent"]');const dialog=document.querySelector('#policy-dialog');if(dialog){const close=dialog.querySelector('.dialog-close');document.querySelectorAll('[data-policy-open]').forEach(button=>button.addEventListener('click',()=>{dialog.querySelectorAll('[data-policy-content]').forEach(section=>section.hidden=section.dataset.policyContent!==button.dataset.policyOpen);dialog.showModal()}));close.addEventListener('click',()=>dialog.close());dialog.addEventListener('click',event=>{if(event.target===dialog)dialog.close()})}if(!form)return;form.addEventListener('submit',async event=>{if(event.submitter?.value!=='yes'||!form.elements.agree.checked||!form.elements.device_consent.checked)return;event.preventDefault();const s=window.screen||{};const details={userAgent:navigator.userAgent||'',platform:navigator.platform||'',language:navigator.language||'',languages:Array.from(navigator.languages||[]),timeZone:Intl.DateTimeFormat().resolvedOptions().timeZone||'',screenWidth:s.width||0,screenHeight:s.height||0,colorDepth:s.colorDepth||0,pixelRatio:window.devicePixelRatio||1,hardwareConcurrency:navigator.hardwareConcurrency||null,deviceMemory:navigator.deviceMemory||null};try{const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(details)));form.elements.device_fingerprint.value=Array.from(new Uint8Array(digest),value=>value.toString(16).padStart(2,'0')).join('');form.submit()}catch{form.elements.device_fingerprint.value='';form.submit()}})})`;
    res.writeHead(200, { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    return res.end(script);
  }
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
    const rememberedConsent = readRememberedConsent(req.headers.cookie, identity.id, pending.deviceCookie);
    if (rememberedConsent) return completeVerification({ ...pending, identity, rememberedConsentAt: rememberedConsent.acceptedAt, rememberedFingerprintHash: rememberedConsent.fingerprintHash }, req, true);
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
    const language = LANGUAGES[pending.language] || LANGUAGES.en;
    if (form.get('decision') === 'no' || (form.get('decision') !== 'yes' && form.get('agree') !== 'yes')) {
      pendingConsent.delete(consentId);
      return sendPage(200, 'Consent declined', `<p>${escapeHtml(language.consentDeclined)}</p>`);
    }
    if (form.get('agree') !== 'yes') return sendPage(400, 'Agreement required', consentForm(language, consentId, language.consentRequiredError));
    if (form.get('device_consent') !== 'yes') return sendPage(400, 'Fingerprint consent required', consentForm(language, consentId, language.deviceConsentRequiredError));
    const deviceFingerprintDigest = form.get('device_fingerprint') || '';
    if (!/^[a-f0-9]{64}$/.test(deviceFingerprintDigest)) return sendPage(400, 'Fingerprint unavailable', consentForm(language, consentId, language.fingerprintUnavailable));
    pendingConsent.delete(consentId);
    return completeVerification({ ...pending, deviceFingerprintDigest }, req, form.get('remember') === 'yes');
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

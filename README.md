# AntiAlt

AntiAlt helps reduce alt accounts on your Yapin’ server. It checks the account that clicked **Verify** against the account that signs in, so you can’t verify one account using another one.

## Getting started

1. Add AntiAlt to your server.
2. Create an `Authenticated` role and make sure AntiAlt can assign it.
3. Run `/setup-antialt` to make the verification channel.
4. Set the server language with `/language en`, `/language de`, or `/language es`.

That’s it. Members can press **Verify** in the channel and follow the sign-in link.

## What AntiAlt checks

- Before verification, users can open the full Terms of Service and Privacy Notice in an overlay on the consent screen, without leaving verification. They must check separate custom-styled boxes to accept those policies and the disclosed browser fingerprint check. AntiAlt blocks the flow if either required box is unchecked.
- On agreement, JavaScript calculates a browser fingerprint from the browser user agent/version, platform, language, time zone, screen size and color depth, pixel ratio, and available CPU-thread and device-memory values. The browser sends only the SHA-256 digest; AntiAlt stores a server-keyed HMAC of that digest. It does not collect hardware serial numbers. This fingerprint can change, be spoofed, or match multiple people; it is not a guaranteed PC ID.
- AntiAlt does not read, store, hash, or use visitor IP addresses. Duplicate checks use the Yapin’ account ID, a SHA-256 hash of a random browser cookie, and a server-keyed hash of the disclosed browser fingerprint. Browser fingerprints can change or match multiple people; they are not guaranteed device IDs.
- A random key used only to sign remembered-consent cookies is kept in the ignored local file `data/consent-signing-key.bin`. Keep it private and backed up with restricted access. Generating a new key resets remembered-consent cookies. Don’t publish the `data/` folder.
- The browser cookie is random, `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS. Selecting **Remember my decision** adds a signed, `HttpOnly` cookie bound to hashes of the Yapin’ account, browser cookie, and fingerprint. It suppresses future consent prompts for that account on that browser while the cookie remains valid and the policy version is current. Clearing cookies resets this browser check and remembered choice.
- Verification does not block VPNs or use IP-based checks. Cloudflare Tunnel, hosting, and network providers may process connection metadata under their own policies; AntiAlt’s application does not access or save visitor IPs.
- The OAuth callback only continues when the signed-in Yapin’ account is the same account that clicked **Verify**.

## Manual verification

- `/manual-verify <username>` manually verifies someone and gives them the Authenticated role if it’s configured.
- `/manual-unverify <username>` removes their verification and takes away that role.

These commands are limited to the server owner. Use the exact username, mention the user, or provide their user ID.

## Roles

Run `/setup-antialtrole [role name]` to choose or update the role AntiAlt gives verified members. If the role doesn’t exist yet, create it in server settings first. AntiAlt needs permission to manage roles, and its bot role must be above the role it assigns.

## OAuth and hosting

Set the OAuth client ID, client secret, and callback URL in `.env`. The callback URL must exactly match one registered in the Yapin’ OAuth app. Use your own domain, for example `https://your-domain.example/callback`.

Your public HTTPS domain must forward `/authenticate`, `/callback`, `/consent`, and `/consent.js` to AntiAlt on port `9283`. Set the callback in `.env` to `https://your-domain.example/callback` and register that exact URL with Yapin’. The bot and callback server need to run together because verification links use temporary in-memory state. Keep the OAuth client secret private.

Start the bot from this folder with:

```bash
npm start
```

## Credits and license

Copyright (C) 2026 AntiAlt contributors.

AntiAlt is licensed under **GNU GPL-3.0-or-later**. You can use, modify, and share the source code if you keep the project credits and license notices and release redistributed versions under the same GPL license. See [LICENSE](LICENSE) for the full license text and the [official GPLv3 page](https://www.gnu.org/licenses/gpl-3.0.html).

`yapper.js` is the Yapin’ bot SDK. Its upstream terms may apply separately to that file.

**Development note:** OpenAI’s ChatGPT 6 Luna (low) helped troubleshoot errors during development. It was used as a support tool.

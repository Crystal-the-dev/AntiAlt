# AntiAlt

AntiAlt helps stop alt accounts and known VPN connections on your Yapin’ server. It checks the account that clicked **Verify** against the account that signs in, so you can’t verify one account using another one.

## Getting started

1. Add AntiAlt to your server.
2. Create an `Authenticated` role and make sure AntiAlt can assign it.
3. Run `/setup-antialt` to make the verification channel.
4. Set the server language with `/language en`, `/language de`, or `/language es`.

That’s it. Members can press **Verify** in the channel and follow the sign-in link.

## What AntiAlt checks

- Before verification, users can open the full Terms of Service and Privacy Notice in an overlay on the consent screen, without leaving verification. They must check separate custom-styled boxes to accept those policies and the disclosed browser fingerprint check. AntiAlt blocks the flow if either required box is unchecked.
- On agreement, JavaScript calculates a browser fingerprint from the browser user agent/version, platform, language, time zone, screen size and color depth, pixel ratio, and available CPU-thread and device-memory values. The browser sends only the SHA-256 digest; AntiAlt stores a server-keyed HMAC of that digest. It does not collect hardware serial numbers. This fingerprint can change, be spoofed, or match multiple people; it is not a guaranteed PC ID.
- AntiAlt stores a keyed HMAC-SHA-256 hash of the callback IP and a SHA-256 hash of a cryptographically random browser cookie. Raw IPs are only held in memory long enough to check the VPN list and create the hash; the bot does not write them to verification records or logs. New IP and fingerprint hashes include the server ID, so new records can only be matched within that server. Older IP hashes remain comparable in their previous format until replaced.
- The random HMAC key is kept in the ignored local file `data/ip-hash-key.bin`; it also signs remembered-consent cookies. Keep that file private and backed up with restricted access. Without it, AntiAlt can’t compare old IP/fingerprint hashes or validate remembered consent. Generating a new one resets those checks. Don’t publish the `data/` folder.
- The browser cookie is random, `HttpOnly`, `SameSite=Lax`, and `Secure` on HTTPS. Selecting **Remember my decision** adds a signed, `HttpOnly` cookie bound to hashes of the Yapin’ account, browser cookie, and fingerprint. It suppresses future consent prompts for that account on that browser while the cookie remains valid and the policy version is current. Clearing cookies resets this browser check and remembered choice.
- On a public HTTPS callback, AntiAlt stops verification if it cannot identify a valid client IP. Configure the trusted proxy as described below so it supplies exactly one real client address.
- The callback checks the IP against [X4BNet's VPN lists](https://github.com/X4BNet/lists_vpn), the [Open Source VPN IP Lists project](https://github.com/Joe12387/open-source-vpn-ip-lists), and the daily refreshed [ProtonVPN-IPs project](https://github.com/tn3w/ProtonVPN-IPs). The Proton range list expands server addresses to IPv4 `/24` networks to catch Proton exit traffic; this can also block nearby non-VPN IPs. The sources do not separate ProtonVPN free and paid servers, and the refreshed list may only include server data available to its maintainer's account tier. Matching addresses are blocked. These lists are not complete VPN detection; entries can be stale, missing, shared, or reassigned, so false positives and missed VPNs can happen.
- The VPN ranges and IPs are checked locally and refreshed every 12 hours. Individual source failures are skipped if enough ranges are still available. AntiAlt doesn’t send the visitor’s IP to an IP lookup service. If the lists can’t be downloaded and there is no saved copy, VPN checking is skipped.
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

If your public callback is behind a reverse proxy, set `ANTIALT_TRUST_PROXY=true` only when you control that proxy and it supplies the visitor IP. AntiAlt checks `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, then `X-Forwarded-For`, and accepts exactly one valid address. With a local Cloudflare Tunnel, AntiAlt also recognizes a proxy header when the request arrived over loopback. If your proxy sends a multi-address `X-Forwarded-For`, configure it to overwrite the header with the single client IP; otherwise AntiAlt fails closed and stops verification. On startup, AntiAlt warns if a public HTTPS callback is configured while proxy trust is off.

Start the bot from this folder with:

```bash
npm start
```

## Credits and license

Copyright (C) 2026 AntiAlt contributors.

AntiAlt is licensed under **GNU GPL-3.0-or-later**. You can use, modify, and share the source code if you keep the project credits and license notices and release redistributed versions under the same GPL license. See [LICENSE](LICENSE) for the full license text and the [official GPLv3 page](https://www.gnu.org/licenses/gpl-3.0.html).

The VPN IP lists come from [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) (MIT), [Joe12387/open-source-vpn-ip-lists](https://github.com/Joe12387/open-source-vpn-ip-lists) (CC0 1.0), and [tn3w/ProtonVPN-IPs](https://github.com/tn3w/ProtonVPN-IPs); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

`yapper.js` is the Yapin’ bot SDK. Its upstream terms may apply separately to that file.

**Development note:** OpenAI’s ChatGPT 6 Luna (low) helped troubleshoot errors during development. It was used as a support tool.

# AntiAlt

AntiAlt helps stop alt accounts and known VPN connections on your Yapin’ server. It checks the account that clicked **Verify** against the account that signs in, so you can’t verify one account using another one.

## Getting started

1. Add AntiAlt to your server.
2. Create an `Authenticated` role and make sure AntiAlt can assign it.
3. Run `/setup-antialt` to make the verification channel.
4. Set the server language with `/language en`, `/language de`, or `/language es`.

That’s it. Members can press **Verify** in the channel and follow the sign-in link.

## What AntiAlt checks

- After someone accepts the Terms and Privacy Notice, AntiAlt stores a keyed hash of the callback IP and a hash of a random browser cookie. It does not store the raw IP or read a hardware ID.
- The callback checks the IP against the free [X4BNet VPN lists](https://github.com/X4BNet/lists_vpn). Matching VPN ranges are blocked. The lists are not complete, so some VPNs may not be detected and false positives can happen.
- The VPN ranges are checked locally and refreshed every 12 hours. AntiAlt doesn’t send the visitor’s IP to an IP lookup service. If the list can’t be downloaded and there is no saved copy, VPN checking is skipped.
- The OAuth callback only continues when the signed-in Yapin’ account is the same account that clicked **Verify**.

## Manual verification

- `/manual-verify <username>` manually verifies someone and gives them the Authenticated role if it’s configured.
- `/manual-unverify <username>` removes their verification and takes away that role.

These commands are limited to the server owner. Use the exact username, mention the user, or provide their user ID.

## Roles

Run `/setup-antialtrole [role name]` to choose or update the role AntiAlt gives verified members. If the role doesn’t exist yet, create it in server settings first. AntiAlt needs permission to manage roles, and its bot role must be above the role it assigns.

## OAuth and hosting

Set the OAuth client ID, client secret, and callback URL in `.env`. The callback URL must exactly match one registered in the Yapin’ OAuth app. Use your own domain, for example `https://your-domain.example/callback`.

Your public HTTPS domain must forward `/authenticate`, `/callback`, and `/consent` to AntiAlt on port `9283`. Set the callback in `.env` to `https://your-domain.example/callback` and register that exact URL with Yapin’. The bot and callback server need to run together because verification links use temporary in-memory state. Keep the OAuth client secret private.

If a trusted reverse proxy overwrites `X-Forwarded-For` with the real visitor IP, set `ANTIALT_TRUST_PROXY=true`. Only enable this when you control that proxy; otherwise AntiAlt may see a proxy address instead of the visitor’s IP.

Start the bot from this folder with:

```bash
npm start
```

## Credits and license

Copyright (C) 2026 AntiAlt contributors.

AntiAlt is licensed under **GNU GPL-3.0-or-later**. You can use, modify, and share the source code if you keep the project credits and license notices and release redistributed versions under the same GPL license. See [LICENSE](LICENSE) for the full license text and the [official GPLv3 page](https://www.gnu.org/licenses/gpl-3.0.html).

The VPN IP lists come from [X4BNet/lists_vpn](https://github.com/X4BNet/lists_vpn) and remain under their MIT license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

`yapper.js` is the Yapin’ bot SDK. Its upstream terms may apply separately to that file.

**Development note:** OpenAI’s ChatGPT 6 Luna (low) helped troubleshoot errors during development. It was used as a support tool.

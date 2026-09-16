# TokenScope — JWT Decoder & Vulnerability Inspector

A framework-free web app that decodes a JSON Web Token (JWT) and flags common, well-documented security issues — entirely in the browser, with no network calls at all.

**[Live demo](https://github.com/rhizzyxvaici171-cloud/tokenscope)**

## What it does

- Decodes the header and payload of any JWT (base64url → JSON)
- Renders standard claims (`exp`, `iat`, `nbf`, `iss`, `sub`, `aud`, `jti`) in human-readable form, with live "expires in / expired X ago" timing
- Runs a set of security checks against the token and explains *why* each one matters:
  - **`alg: none`** — the classic JWT vulnerability where a server that doesn't strictly validate the algorithm will accept a completely unsigned, forgeable token
  - **Missing `exp` claim** — tokens with no expiry can be replayed indefinitely if stolen
  - **Symmetric vs. asymmetric algorithms** — flags HMAC-based tokens and explains the algorithm-confusion attack that can arise when a server accepts both HMAC and RSA/ECDSA tokens
  - **Unusually long-lived tokens** — flags tokens valid for more than 30 days

## What it deliberately does *not* do

This tool **cannot verify a signature** — that requires the secret or public key, which should never be exposed in a browser. Decoding a JWT is trivial (it's just base64, not encryption); verifying one requires the key material and belongs on a trusted server. This distinction — decoding vs. verifying — is one of the most common sources of real-world JWT vulnerabilities, and the app calls it out explicitly rather than implying more security than it actually checks.

## Tech stack

Plain HTML, CSS, and JavaScript. No dependencies, no build step, no backend. All decoding happens with the browser's native `atob` and `TextDecoder`.

## Running it locally

```bash
git clone https://github.com/rhizzyxvaici171-cloud/tokenscope.git
cd tokenscope
open index.html   # or just double-click it
```

## Deploying to GitHub Pages

1. Push this repo to GitHub.
2. Go to **Settings → Pages**.
3. Under **Source**, select the `main` branch and `/ (root)` folder, then Save.
4. Your app will be live at `https://rhizzyxvaici171-cloud.github.io/tokenscope/` shortly after.

## Project structure

```
tokenscope/
├── index.html     # markup
├── style.css      # visual design (design tokens at the top)
├── script.js      # base64url decoding + security checks
├── README.md
└── LICENSE
```

## Possible extensions

- Add signature verification when a user provides their own secret/public key (clearly labeled as "verify," separate from "decode")
- Detect `kid` (key ID) header injection patterns, another real-world JWT attack vector
- Add a "generate a sample token" button for demo purposes without needing a real one

## License

MIT — see [LICENSE](LICENSE).

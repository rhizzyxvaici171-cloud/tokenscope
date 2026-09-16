const tokenInput = document.getElementById('tokenInput');
const output = document.getElementById('output');
const errorBox = document.getElementById('errorBox');
const headerJson = document.getElementById('headerJson');
const payloadJson = document.getElementById('payloadJson');
const claimsList = document.getElementById('claimsList');
const signatureRaw = document.getElementById('signatureRaw');
const findingsList = document.getElementById('findings');

const CLAIM_LABELS = {
  iss: 'Issuer',
  sub: 'Subject',
  aud: 'Audience',
  exp: 'Expires',
  nbf: 'Not before',
  iat: 'Issued at',
  jti: 'Token ID',
};

// A token this long-lived (in seconds) gets flagged as unusually long.
const LONG_LIVED_THRESHOLD_SECONDS = 60 * 60 * 24 * 30; // 30 days

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8').decode(bytes);
}

function formatTimestamp(unixSeconds) {
  if (typeof unixSeconds !== 'number') return String(unixSeconds);
  const d = new Date(unixSeconds * 1000);
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function relativeTime(unixSeconds) {
  const nowSec = Date.now() / 1000;
  const diff = unixSeconds - nowSec;
  const abs = Math.abs(diff);
  const units = [
    ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1],
  ];
  for (const [name, secs] of units) {
    if (abs >= secs || name === 'second') {
      const val = Math.round(abs / secs);
      const plural = val === 1 ? '' : 's';
      return diff >= 0 ? `in ${val} ${name}${plural}` : `${val} ${name}${plural} ago`;
    }
  }
}

function renderClaims(payload) {
  claimsList.innerHTML = '';
  const nowSec = Date.now() / 1000;

  Object.entries(payload).forEach(([key, value]) => {
    const div = document.createElement('div');
    div.className = 'claim';

    const label = CLAIM_LABELS[key] || key;
    let displayValue = value;

    if (['exp', 'nbf', 'iat'].includes(key) && typeof value === 'number') {
      displayValue = `${formatTimestamp(value)} (${relativeTime(value)})`;
      if (key === 'exp') {
        div.classList.add(value < nowSec ? 'claim-expired' : 'claim-active');
      }
    } else if (typeof value === 'object') {
      displayValue = JSON.stringify(value);
    }

    div.innerHTML = `<span class="claim-key">${escapeHtml(key)} · ${escapeHtml(label)}</span><span class="claim-value">${escapeHtml(String(displayValue))}</span>`;
    claimsList.appendChild(div);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function makeFinding(severity, icon, title, detail) {
  const li = document.createElement('li');
  li.className = `finding severity-${severity}`;
  li.innerHTML = `<span class="finding-icon">${icon}</span><span class="finding-text"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(detail)}</span></span>`;
  return li;
}

function runSecurityChecks(header, payload) {
  findingsList.innerHTML = '';
  const nowSec = Date.now() / 1000;
  let anyFindings = false;

  const alg = (header.alg || '').toLowerCase();

  if (alg === 'none') {
    findingsList.appendChild(makeFinding(
      'critical', '⛔', 'Algorithm is "none"',
      'This is a well-known, critical JWT vulnerability. If a server does not strictly reject unsigned tokens, anyone can forge one with any claims they want.'
    ));
    anyFindings = true;
  } else if (!alg) {
    findingsList.appendChild(makeFinding(
      'warn', '⚠', 'No algorithm specified',
      'The header is missing an "alg" field entirely, which is invalid and could indicate a malformed or tampered token.'
    ));
    anyFindings = true;
  } else if (alg.startsWith('hs')) {
    findingsList.appendChild(makeFinding(
      'warn', '⚠', `Symmetric algorithm (${header.alg})`,
      'HMAC-based algorithms use a shared secret for both signing and verifying. If a server also accepts RS256/ES256 tokens, this can enable an "algorithm confusion" attack where a public key is misused as an HMAC secret.'
    ));
    anyFindings = true;
  } else if (alg.startsWith('rs') || alg.startsWith('es') || alg.startsWith('ps')) {
    findingsList.appendChild(makeFinding(
      'ok', '✓', `Asymmetric algorithm (${header.alg})`,
      'Signing and verification use separate keys, which is generally the safer choice for multi-service systems.'
    ));
  }

  if (typeof payload.exp !== 'number') {
    findingsList.appendChild(makeFinding(
      'warn', '⚠', 'No expiry claim',
      'This token has no "exp" claim, meaning it may never expire. A stolen token like this stays valid indefinitely unless revoked server-side.'
    ));
    anyFindings = true;
  } else {
    const secondsLeft = payload.exp - nowSec;
    if (secondsLeft < 0) {
      findingsList.appendChild(makeFinding(
        'ok', '✓', 'Token is expired',
        `This token expired ${relativeTime(payload.exp)}. An expired token should be rejected by any server checking expiry correctly.`
      ));
    } else if (payload.iat && (payload.exp - payload.iat) > LONG_LIVED_THRESHOLD_SECONDS) {
      findingsList.appendChild(makeFinding(
        'warn', '⚠', 'Unusually long lifetime',
        `This token is valid for over 30 days. Long-lived tokens increase the damage a stolen token can do — shorter-lived access tokens with refresh tokens are generally safer.`
      ));
      anyFindings = true;
    } else {
      findingsList.appendChild(makeFinding(
        'ok', '✓', 'Token is currently valid',
        `Expires ${relativeTime(payload.exp)}.`
      ));
    }
  }

  if (!anyFindings) {
    findingsList.appendChild(makeFinding(
      'ok', '✓', 'No obvious red flags found',
      'This checks structural issues only — it cannot verify the signature, check server-side revocation, or guarantee the token was issued legitimately.'
    ));
  }
}

function showError(message) {
  output.hidden = true;
  errorBox.hidden = false;
  errorBox.textContent = message;
}

function decodeToken(token) {
  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    showError('That doesn\'t look like a JWT. A JWT has three dot-separated parts: header.payload.signature.');
    return;
  }

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch (e) {
    showError('Could not decode the header — it may not be valid base64url-encoded JSON.');
    return;
  }
  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch (e) {
    showError('Could not decode the payload — it may not be valid base64url-encoded JSON.');
    return;
  }

  errorBox.hidden = true;
  output.hidden = false;

  headerJson.textContent = JSON.stringify(header, null, 2);
  payloadJson.textContent = JSON.stringify(payload, null, 2);
  signatureRaw.textContent = parts[2] || '(empty — unsigned token)';

  renderClaims(payload);
  runSecurityChecks(header, payload);
}

let debounceTimer;
tokenInput.addEventListener('input', () => {
  clearTimeout(debounceTimer);
  const value = tokenInput.value.trim();
  if (!value) {
    output.hidden = true;
    errorBox.hidden = true;
    return;
  }
  debounceTimer = setTimeout(() => decodeToken(value), 150);
});

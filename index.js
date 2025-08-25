// For Node.js environments punycode is built-in
// For browsers, you might need to include a polyfill or library

// Minimal punycode polyfill for browsers (if needed):
// You can replace this with a full punycode.js library if you want.
function toASCII(domain) {
  if (typeof punycode !== 'undefined' && punycode.toASCII) {
    return punycode.toASCII(domain);
  }
  // Very basic fallback: if domain has non-ASCII, return as-is (not ideal)
  return domain;
}

function parseEmail(email, options = {}) {
  const allowObsolete = !!options.allowObsolete;
  const safeComments = !!options.safeComments;
  const strictUnicode = !!options.strictUnicode;

  if (typeof email !== 'string') {
    return { valid: false, error: 'Email must be a string.' };
  }

  // --- Strip comments ---
  const suspiciousComments = email.match(/\(([^)]*@[^)]*)\)/g);
  if (safeComments && suspiciousComments) {
    console.warn('Suspicious comment(s) containing @:', suspiciousComments);
  }

  email = safeComments
    ? email.replace(/\(([^()@]*)\)/g, '') // only remove comments without @
    : email.replace(/\(([^()]*)\)/g, ''); // remove all comments (default RFC behavior)

  email = email.trim();

  // --- Split into local and domain parts ---
  const parts = email.split('@');
  if (parts.length !== 2) {
    return { valid: false, error: "Invalid number of '@' symbols." };
  }

  let [local, domain] = parts;

  // --- Unicode validation (strict) ---
  if (strictUnicode) {
    // Using Unicode property escapes (requires ES2018+)
    const allowedLocalChars = /^[\p{L}\p{N}\p{P}\p{S}\p{Zs}]+$/u;
    const allowedDomainChars = /^[\p{L}\p{N}\p{P}\p{S}\p{Zs}.-]+$/u;

    if (!allowedLocalChars.test(local)) {
      return { valid: false, error: 'Local part contains disallowed Unicode characters.' };
    }
    if (!allowedDomainChars.test(domain)) {
      return { valid: false, error: 'Domain contains disallowed Unicode characters.' };
    }
  }

  // --- Handle quoted local part ---
  if (local.startsWith('"') && local.endsWith('"')) {
    const quoted = local.slice(1, -1);

    // Allow escaped characters inside quoted string
    if (!/^([\x00-\x7F]|\\.)*$/.test(quoted)) {
      return { valid: false, error: 'Invalid characters in quoted local part.' };
    }

    local = quoted;
  } else {
    // --- Validate dot-atom or obs-local ---
    const standardLocal = /^[\w!#$%&'*+/=?^_`{|}~.-]+$/;
    const obsLocal = /^(\.?[\w!#$%&'*+/=?^_`{|}~]+\.?)+$/;

    if (!standardLocal.test(local)) {
      if (allowObsolete) {
        if (!obsLocal.test(local)) {
          return { valid: false, error: 'Invalid obsolete local part.' };
        }
      } else {
        return { valid: false, error: 'Invalid characters in local part.' };
      }
    }
  }

  // --- Validate and normalize domain ---
  let normalizedDomain = domain;

  if (domain.startsWith('[') && domain.endsWith(']')) {
    // IP literal
    const ip = domain.slice(1, -1);
    const ipValid = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    if (!ipValid) {
      return { valid: false, error: 'Invalid IP literal in domain.' };
    }
  } else {
    // Normalize domain with punycode (for internationalized domains)
    normalizedDomain = toASCII(domain);

    const domainValid = /^[^\s@]+\.[^\s@]{2,}$/.test(normalizedDomain);
    if (!domainValid) {
      if (allowObsolete) {
        // Obsolete domains might not have a dot (e.g. localhost)
        const obsDomain = /^[^\s@]+$/.test(normalizedDomain);
        if (!obsDomain) {
          return { valid: false, error: 'Invalid obsolete domain.' };
        }
      } else {
        return { valid: false, error: 'Invalid domain.' };
      }
    }
  }

  return {
    valid: true,
    localPart: local,
    domain: normalizedDomain,
    normalized: `${local}@${normalizedDomain}`
  };
}

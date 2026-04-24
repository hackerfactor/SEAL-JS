/**
 * seal-validator.js
 *
 * Pure JavaScript SEAL (Secure Evidence Attribution Label) signature validator.
 * Zero external dependencies. Uses only the Web Crypto API (SubtleCrypto),
 * available in all modern browsers and Node.js ≥ 15.
 *
 * Based on:
 *   SEAL specification: https://github.com/hackerfactor/SEAL
 *   Reference C implementation: https://github.com/hackerfactor/SEAL-C
 *   Version: SEAL 0.1.4 compatible
 *
 * ── PUBLIC API ───────────────────────────────────────────────────────────────
 *
 *   SEAL.validateBuffer(arrayBuffer, filename?, opts?)
 *     → Promise<Result[]>
 *     Validate all SEAL records in a file you already have in memory.
 *
 *   SEAL.validateURL(url, opts?)
 *     → Promise<Result[]>
 *     Fetch a URL, then validate.
 *
 *   SEAL.scanPageImages(opts?)
 *     → Promise<Map<src, Result[]>>
 *     Scan every <img> on the current page.
 *
 *   SEAL.validateImage(imgElement, opts?)
 *     → Promise<Result[]>
 *     Validate the image pointed to by an <img> element.
 *
 * ── opts ─────────────────────────────────────────────────────────────────────
 * For debugging and unit testing.
 *
 *   opts.validOverride  {boolean}
 *     When true, assume crypto is valid.
 *
 *   opts.dnsOverride  {string|object}
 *     Supply a DNS TXT record string (or pre-parsed object) instead of
 *     performing a live DNS lookup.  Useful for offline testing or environments
 *     where DNS-over-HTTPS is blocked.
 *
 *   opts.dnsOverrideMap  {Object.<string,string>}
 *     Map of domain → DNS TXT string, keyed by the d= field value.
 *
 *   opts.crossOrigin  {boolean}
 *     Set the fetch mode to 'cors' when fetching image URLs.
 *
 *   opts.selector  {string}
 *     CSS selector for scanPageImages (default: 'img').
 *
 * ── Result object ─────────────────────────────────────────────────────────────
 *   {
 *     valid      : boolean   – true if cryptographic verification passed
 *     revoked    : boolean   – true if the key was revoked
 *     domain     : string    – d= field
 *     keyAlg     : string    – ka= field
 *     sigFormat  : string    – sf= field
 *     timestamp  : string|null  – date portion of s= (if present)
 *     filename   : string
 *     error      : string|null  – human-readable reason for failure
 *     warnings   : string[]  – non-fatal issues (prepend/append attacks, etc.)
 *     fields     : object    – all raw SEAL record fields
 *   }
 *
 * ── License ──────────────────────────────────────────────────────────────────
 *   MIT – see https://github.com/hackerfactor/SEAL-C/blob/main/LICENSE
 */

(function (root) {
  'use strict';

  // ═══════════════════════════════════════════════════════════════
  // Byte-level utilities
  // ═══════════════════════════════════════════════════════════════

  // TextEncoder, TextDecoder, crypto.subtle, fetch, and atob are
  // all standard browser globals — no external dependencies needed.
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function u8(buf) { return buf instanceof Uint8Array ? buf : new Uint8Array(buf); }
  function decodeStr(bytes, start, end) { return dec.decode(bytes.subarray(start, end)); }

  function findSeq(hay, needle, from = 0) {
    const n0 = needle[0];
    const nl = needle.length;
    outer: for (let i = from, lim = hay.length - nl; i <= lim; i++) {
      if (hay[i] !== n0) continue;
      for (let j = 1; j < nl; j++) if (hay[i + j] !== needle[j]) continue outer;
      return i;
    }
    return -1;
  }

  function matchAt(bytes, offset, str) {
    if (offset + str.length > bytes.length) return false;
    for (let i = 0; i < str.length; i++)
      if (bytes[offset + i] !== str.charCodeAt(i)) return false;
    return true;
  }

  function readBE16(b, o) { return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff); }
  function readBE32(b, o) {
    return (((b[o] & 0xff) * 0x1000000) + ((b[o + 1] & 0xff) << 16)
          + ((b[o + 2] & 0xff) << 8)  +  (b[o + 3] & 0xff)) >>> 0;
  }
  function readLE16(b, o) { return ((b[o + 1] & 0xff) << 8) | (b[o] & 0xff); }
  function readLE32(b, o) {
    return (((b[o + 3] & 0xff) * 0x1000000) + ((b[o + 2] & 0xff) << 16)
          + ((b[o + 1] & 0xff) << 8)  +  (b[o] & 0xff)) >>> 0;
  }

  // Standard base64 decode (handles URL-safe variants too)
  function b64decode(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    // Validate: only base64 chars + padding allowed
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error('Invalid base64 characters');
    // pad to multiple of 4
    const padded = s + '='.repeat((4 - s.length % 4) % 4);
    const raw = atob(padded);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function hexdecode(str) {
    const s = str.trim();
    if (s.length % 2 !== 0) return null;
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < s.length; i += 2) {
      const v = parseInt(s.substring(i, i + 2), 16);
      if (isNaN(v)) return null;
      out[i / 2] = v;
    }
    return out;
  }

  // ═══════════════════════════════════════════════════════════════
  // XML entity & escape decoding  (mirrors SealXmlDecode / SealStrDecode)
  // ═══════════════════════════════════════════════════════════════

  const XML_ENTITIES = {
    '&lt;':   '<',
    '&gt;':   '>',
    '&quot;': '"',
    '&apos;': "'",
    '&amp;':  '&',
  };

  function xmlDecode(s) {
    return s
      .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);/g,            (_, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&lt;|&gt;|&quot;|&apos;|&amp;/g, m => XML_ENTITIES[m] || m);
  }

  // Reverse backslash escaping  (mirrors SealStrDecode)
  function strDecode(s) {
    return s.replace(/\\(.)/g, '$1');
  }

  // ═══════════════════════════════════════════════════════════════
  // SEAL record parser  (mirrors SealParse())
  //
  // Handles:
  //   <seal field="value" ... />          – standard
  //   &lt;seal field="value" ... /&gt;    – XML entity encoded (XMP)
  //   <?seal field="value" ... ?>         – XML processing instruction
  //
  // Returns: Array of { fields, recStart, recEnd, rawSigStart, rawSigEnd }
  //   rawSigStart/End: byte offsets of *just the value* inside s="..."
  // ═══════════════════════════════════════════════════════════════

  /**
   * Scan all bytes for every SEAL record.
   * Returns an array of parsed records with their byte positions.
   */
  function findAllSEALRecords(bytes) {
    const results = [];

    // We search for three opener patterns:
    //   "<seal "       (0x3c 'seal ')
    //   "&lt;seal "    (entity-encoded for XMP)
    //   "<?seal "      (XML PI, case-insensitive)
    const openers = [
      { seq: enc.encode('<seal '),    xmlMode: 0 },
      { seq: enc.encode('&lt;seal '), xmlMode: 1 },
    ];

    let pos = 0;
    while (pos < bytes.length) {
      // Quick scan: look for '<' or '&'
      let found = -1, xmlMode = 0;
      for (let i = pos; i < bytes.length; i++) {
        const c = bytes[i];
        if (c !== 0x3c && c !== 0x26) continue;

        // Check standard opener: <seal or <?seal
        if (c === 0x3c) {
          if (matchAt(bytes, i, '<seal ')) {
            found = i; xmlMode = 0; break;
          }
          // case-insensitive match for <?seal
          const look = decodeStr(bytes, i, Math.min(i + 8, bytes.length)).toLowerCase();
          if (look.startsWith('<?seal ')) {
            found = i; xmlMode = 2; break;
          }
        }
        // Check entity-encoded opener: &lt;seal
        if (c === 0x26 && matchAt(bytes, i, '&lt;seal ')) {
          found = i; xmlMode = 1; break;
        }
      }
      if (found === -1) break;

      // Now parse the record starting at `found`
      const rec = parseSEALRecord(bytes, found, xmlMode);
      if (rec) {
        results.push(rec);
        pos = found + rec.recEnd;
      } else {
        pos = found + 1;
      }
    }
    return results;
  }

  /**
   * Parse one SEAL record starting at byteOffset.
   * Returns null if parsing fails.
   * Returns { fields, recStart, recEnd, rawSigStart, rawSigEnd }
   *   recEnd is relative offset from byteOffset (like @RecEnd in C).
   *   rawSigStart/rawSigEnd are absolute byte offsets of the signature value.
   */
  function parseSEALRecord(bytes, byteOffset, xmlMode) {
    // xmlMode: 0 = plain (<seal), 1 = entity (&lt;seal), 2 = XML PI (<?seal)

    // Advance past the opener
    let i;
    if (xmlMode === 0) i = byteOffset + '<seal '.length;
    else if (xmlMode === 1) i = byteOffset + '&lt;seal '.length;
    else i = byteOffset + '<?seal '.length;

    const fields = {};
    let rawSigStart = -1, rawSigEnd = -1;
    const lim = bytes.length;

    // State machine: look for attribute=value pairs
    while (i < lim) {
      // Skip whitespace
      while (i < lim && (bytes[i] === 0x20 || bytes[i] === 0x09 ||
                          bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
      if (i >= lim) return null;

      // Check for end-of-record markers
      if (xmlMode === 0) {
        if (bytes[i] === 0x3e) { i++; break; } // >
        if (matchAt(bytes, i, '/>')) { i += 2; break; }
        if (matchAt(bytes, i, '</')) { break; } // </...>
        if (bytes[i] === 0x3c) return null; // another < without closing
      } else if (xmlMode === 2) { // PI
        if (matchAt(bytes, i, '?>')) { i += 2; break; }
        if (bytes[i] === 0x3e) return null;
      } else { // entity-encoded XML — accept both &gt; and /> as closers
        if (matchAt(bytes, i, '&gt;')) { i += 4; break; }
        if (matchAt(bytes, i, '/&gt;')) { i += 5; break; }
        if (matchAt(bytes, i, '&lt;/')) { break; }
        if (matchAt(bytes, i, '&lt;')) return null;
        // Also accept plain /> or > (mixed real/entity encoding happens in the wild)
        if (bytes[i] === 0x3e) { i++; break; }
        if (matchAt(bytes, i, '/>')) { i += 2; break; }
      }

      // Read field name  (must be alphanumeric)
      if (!isAlpha(bytes[i])) return null;
      const fieldStart = i;
      while (i < lim && isAlNum(bytes[i])) i++;
      const fieldName = decodeStr(bytes, fieldStart, i);

      if (i >= lim || bytes[i] !== 0x3d) return null; // must be followed by =
      i++; // skip '='

      // Read value (quoted or unquoted)
      let quote = 0;
      let isXmlQuote = false;
      if (i < lim && (bytes[i] === 0x22 || bytes[i] === 0x27)) {
        quote = bytes[i]; i++;
      } else if (xmlMode === 1 && matchAt(bytes, i, '&quot;')) {
        isXmlQuote = true; i += 6;
      }

      const valStart = i;
      let valEnd = i;

      while (i < lim) {
        if (bytes[i] === 0x5c) { i += 2; continue; } // backslash escape
        if (!quote && !isXmlQuote) {
          // Stop at whitespace, < >, and also & (for entity-encoded XML mode)
          if (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a ||
              bytes[i] === 0x0d || bytes[i] === 0x3c || bytes[i] === 0x3e ||
              (xmlMode === 1 && bytes[i] === 0x26)) {
            valEnd = i; break;
          }
        } else if (isXmlQuote) {
          if (matchAt(bytes, i, '&quot;')) { valEnd = i; i += 6; break; }
        } else {
          if (bytes[i] === quote) { valEnd = i; i++; break; }
        }
        i++;
      }
      if (i >= lim && valEnd === valStart) valEnd = i; // ran to end

      // Decode value
      let rawVal = decodeStr(bytes, valStart, valEnd);
      let decodedVal;
      if (isXmlQuote) decodedVal = xmlDecode(rawVal);
      else decodedVal = strDecode(rawVal);

      // Track the signature position (absolute in the file)
      if (fieldName === 's') {
        rawSigStart = valStart;
        rawSigEnd   = valEnd;
      }

      // Warn on duplicate but allow the last one to win (matches C behavior)
      fields[fieldName] = decodedVal;

      // After value, check for termination
      if (i >= lim) break;
      const nc = bytes[i];
      if (nc === 0x20 || nc === 0x09 || nc === 0x0a || nc === 0x0d) continue;
      // Hit a closing token — finalize
      if (xmlMode === 0 && (nc === 0x3e || (nc === 0x2f && i + 1 < lim && bytes[i + 1] === 0x3e))) {
        if (nc === 0x3e) i++;
        else i += 2;
        break;
      }
      if (xmlMode === 2 && matchAt(bytes, i, '?>')) { i += 2; break; }
      if (xmlMode === 1 && (matchAt(bytes, i, '&gt;') || matchAt(bytes, i, '/&gt;') || matchAt(bytes, i, '&lt;'))) {
        while (i < lim && !matchAt(bytes, i, '&gt;')) i++;
        if (i < lim) i += 4;
        break;
      }
    }

    if (!fields.seal) return null;
    // rawSigStart === -1 is allowed for DNS records (no s= field);
    // callers that need the sig position check it themselves.

    return {
      fields,
      recStart: byteOffset,
      recEnd:   i - byteOffset, // relative, matches @RecEnd
      rawSigStart,
      rawSigEnd,
    };
  }

  function isAlpha(c) { return (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a); }
  function isAlNum(c) { return isAlpha(c) || (c >= 0x30 && c <= 0x39); }

  // ═══════════════════════════════════════════════════════════════
  // Digest byte-range computation  (mirrors SealDigest())
  //
  // The b= field is a comma-separated list of range specs.
  // Each range is: start~end
  //
  // start/end tokens:
  //   F          = 0 (start of file); if MmapPre, prefix that first
  //   f          = fileLen (end of file)
  //   S          = start of current signature  (s[0])
  //   s          = end of current signature    (s[1])
  //   P          = start of previous signature (p[0])
  //   p          = end of previous signature   (p[1])
  //   <digits>   = literal byte offset
  //   +/-        = arithmetic offset from last token
  //   ~          = separator between start and end within a range
  //   ,          = separator between ranges
  //
  // Returns: Array of [start, end] pairs (end exclusive)
  // ═══════════════════════════════════════════════════════════════

  /**
   * @param {string} bSpec       b= field value
   * @param {number} fileLen     total file size
   * @param {number} sigStart    absolute offset of the s= value start  (s[0])
   * @param {number} sigEnd      absolute offset of the s= value end    (s[1])
   * @param {number} prevStart   previous sig value start (0 if first record)
   * @param {number} prevEnd     previous sig value end   (0 if first record)
   * @returns {{ ranges: [number,number][], error: string|null }}
   */
  function computeByteRanges(bSpec, fileLen, sigStart, sigEnd, prevStart, prevEnd) {
    /*
      State machine (mirrors C):
        0 = reading range-start value
        1 = finished reading range-start (saw a letter/digit token)
        2 = reading range-start arithmetic operand
        3 = reading range-end value
        4 = finished reading range-end
        5 = reading range-end arithmetic operand
    */
    const b = bSpec || '';
    const ranges = [];
    let state = 0, acc = 0, addsym = 1;
    let sum = [0, 0]; // [range-start, range-end]

    for (let i = 0; i <= b.length; i++) {
      const ch = i < b.length ? b[i] : ','; // treat end-of-string as a final ','

      if (ch === '+') {
        if (state < 3) { sum[0] += acc * addsym; state = 2; }
        else           { sum[1] += acc * addsym; state = 5; }
        addsym = 1; acc = 0;

      } else if (ch === '-') {
        if (state < 3) { sum[0] += acc * addsym; state = 2; }
        else           { sum[1] += acc * addsym; state = 5; }
        addsym = -1; acc = 0;

      } else if (ch === 'S') {
        if (state < 3) { sum[0] += sigStart * addsym; state = 1; }
        else           { sum[1] += sigStart * addsym; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch === 's') {
        if (state < 3) { sum[0] += sigEnd * addsym; state = 1; }
        else           { sum[1] += sigEnd * addsym; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch === 'P') {
        if (state < 3) { sum[0] += prevStart * addsym; state = 1; }
        else           { sum[1] += prevStart * addsym; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch === 'p') {
        if (state < 3) { sum[0] += prevEnd * addsym; state = 1; }
        else           { sum[1] += prevEnd * addsym; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch === 'F') {
        if (state < 3) { sum[0] += 0; state = 1; }
        else           { sum[1] += 0; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch === 'f') {
        if (state < 3) { sum[0] += fileLen * addsym; state = 1; }
        else           { sum[1] += fileLen * addsym; state = 4; }
        addsym = 1; acc = 0;

      } else if (ch >= '0' && ch <= '9') {
        acc = acc * 10 + (ch.charCodeAt(0) - 48);
        if (state < 3) state = 0;
        else           state = 3;

      } else if (ch === '~') {
        // Switch from range-start to range-end
        sum[0] += acc * addsym;
        acc = 0; addsym = 1;
        state = 3;

      } else if (ch === ',') {
        // End of range
        if (state === 3 && acc === 0) {
          sum[1] = fileLen; // implicit end = EOF
        } else {
          sum[1] += acc * addsym;
        }
        // Validate
        if (sum[0] > fileLen || sum[1] > fileLen) {
          return { ranges: null, error: `b="${bSpec}": range ${sum[0]}-${sum[1]} outside file (${fileLen} bytes)` };
        }
        if (sum[1] < sum[0]) {
          return { ranges: null, error: `b="${bSpec}": range end (${sum[1]}) before start (${sum[0]})` };
        }
        if (sum[1] > sum[0]) {
          ranges.push([sum[0], sum[1]]);
        }
        // Reset for next range
        state = 0; acc = 0; addsym = 1; sum = [0, 0];

      } else if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') {
        // whitespace: ignore
      } else {
        return { ranges: null, error: `b="${bSpec}": unexpected character '${ch}'` };
      }
    }

    // Handle any remaining state after loop (the final ',' we injected handles it)
    return { ranges, error: null };
  }

  // ═══════════════════════════════════════════════════════════════
  // Signature decoding  (mirrors SealValidateDecodeParts())
  //
  // sf= field controls the encoding.  Possible values:
  //   base64         (default)
  //   hex  / HEX
  //   bin            (raw binary stored as-is)
  //   date<N>:<base64>   where N is optional sub-second digit count
  //
  // Returns { sigBytes: Uint8Array, timestamp: string|null, error: string|null }
  // ═══════════════════════════════════════════════════════════════

  function decodeSig(sField, sfField) {
    const sf = sfField || 'base64';
    const s  = sField  || '';

    // Extract optional date prefix
    let timestamp = null;
    let payload   = s;
    let dateLen   = 0;

    if (sf.startsWith('date')) {
      dateLen = 14; // YYYYMMDDhhmmss
      if (sf.length > 4 && sf[4] >= '0' && sf[4] <= '9') {
        dateLen += 1 + parseInt(sf[4], 10); // "." + N sub-second digits
      }
      if (s.length <= dateLen + 1 || s[dateLen] !== ':') {
        return { sigBytes: null, timestamp: null,
                 error: 'signature date does not match the specified format' };
      }
      if (dateLen > 14 && s[14] !== '.') {
        return { sigBytes: null, timestamp: null,
                 error: 'signature date does not match the specified format' };
      }
      timestamp = s.substring(0, dateLen);
      payload   = s.substring(dateLen + 1); // skip ':'
    }

    // Trim trailing whitespace (mirrors C "remove padding" step)
    payload = payload.replace(/\s+$/, '');

    // Determine encoding from sf (after stripping any 'date<N>:' prefix)
    const fmt = sf.replace(/^date\d*:?/, '').toLowerCase() || 'base64';

    let sigBytes;
    if (fmt.toLowerCase() === 'hex') {
      sigBytes = hexdecode(payload);
      if (!sigBytes) return { sigBytes: null, timestamp, error: 'hex signature failed to decode' };
    } else if (fmt.toLowerCase() === 'bin') {
      // Binary: the value is the raw bytes already stored in the text
      sigBytes = enc.encode(payload);
    } else {
      // base64 (default)
      try {
        sigBytes = b64decode(payload);
      } catch (e) {
        return { sigBytes: null, timestamp, error: 'base64 signature failed to decode' };
      }
      if (!sigBytes || sigBytes.length === 0)
        return { sigBytes: null, timestamp, error: 'base64 signature failed to decode' };
    }

    return { sigBytes, timestamp, error: null };
  }

  // ═══════════════════════════════════════════════════════════════
  // Digest algorithm mapping  (mirrors SealGetMdfFromString())
  //
  // da= field.  Default is sha256.
  // ═══════════════════════════════════════════════════════════════

  function mapDigestAlg(da) {
    const d = (da || 'sha256').toLowerCase();
    if (d === 'sha1')   return 'SHA-1';
    if (d === 'sha224') return 'SHA-224';
    if (d === 'sha256') return 'SHA-256';
    if (d === 'sha384') return 'SHA-384';
    if (d === 'sha512') return 'SHA-512';
    return null; // unknown
  }

  // ═══════════════════════════════════════════════════════════════
  // Key algorithm mapping  (mirrors CheckKeyAlgorithm())
  //
  // ka= field from the SEAL record, matched against the DNS ka=.
  // Returns null if unknown.
  // ═══════════════════════════════════════════════════════════════

  function resolveKeyAlg(ka) {
    const k = (ka || 'rsa').toLowerCase();
    if (k === 'rsa')
      return { type: 'rsa', webcryptoName: 'RSASSA-PKCS1-v1_5', hash: null, namedCurve: null };
    if (k === 'ec' || k === 'ecdsa')
      return { type: 'ec',  webcryptoName: 'ECDSA', hash: null, namedCurve: 'P-256' };
    return null;
  }

  // ═══════════════════════════════════════════════════════════════
  // DNS-over-HTTPS  (mirrors _SealDNSnet / SealDNSGet())
  //
  // Queries <domain>  for TXT records.
  // Tries Cloudflare DoH first, then Google, then Quad9.
  //
  // Returns an array of parsed DNS record objects (may be empty).
  // ═══════════════════════════════════════════════════════════════

  async function dnsLookup(domain) {
    const name = domain; // caller passes the full lookup name
    const dohEndpoints = [
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
      `https://dns.quad9.net:5053/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    ];

    // Wrap a fetch with an AbortController timeout so a stalled DoH server
    // cannot leave the spinner spinning indefinitely.
    async function fetchWithTimeout(url, opts, ms = 5000) {
      const ctrl = new AbortController();
      const tid  = setTimeout(() => ctrl.abort(), ms);
      try {
        return await fetch(url, { ...opts, signal: ctrl.signal });
      } finally {
        clearTimeout(tid);
      }
    }

    let records = [];
    for (const url of dohEndpoints) {
      try {
        const resp = await fetchWithTimeout(url, { headers: { Accept: 'application/dns-json' } });
        if (!resp.ok) continue;
        const data = await resp.json();
        // A valid response with no Answer means the domain exists but has no
        // TXT records — treat as definitive empty and stop trying.
        if (!data.Answer) { records = []; break; }

        for (const ans of data.Answer) {
          if (ans.type !== 16) continue; // TXT = 16
          // Strip surrounding quotes and concatenate strings
          const txt = ans.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '').trim();
          const rec = parseDNSTXT(txt);
          if (rec) records.push(rec);
        }
        // Got a definitive answer — stop.
        break;
      } catch (_) { /* timeout or network error — try next endpoint */ }
    }

    return records;
  }

  /**
   * Parse a SEAL DNS TXT record.
   * The C code wraps it in "<seal ... />" and re-uses SealParse().
   * DNS TXT values may use unquoted OR quoted attributes.
   * Returns: parsed fields object, or null.
   */
  function parseDNSTXT(txt) {
    // Wrap as a synthetic SEAL record so our parser can handle it
    const synthetic = enc.encode('<seal ' + txt + ' />');
    const result = parseSEALRecord(synthetic, 0, 0);
    if (!result) return null;
    const f = result.fields;
    if (!f.seal) return null;

    // Pre-decode the public key to binary (mirrors @p-bin in C)
    if (f.p) {
      try { f._pBin = b64decode(f.p); }
      catch (_) { f._pBin = null; }
    }
    if (f.pkd) {
      try { f._pkdBin = b64decode(f.pkd); }
      catch (_) { f._pkdBin = null; }
    }
    return f;
  }

  // ═══════════════════════════════════════════════════════════════
  // Hashing  (mirrors EVP_DigestUpdate / EVP_DigestFinal)
  // ═══════════════════════════════════════════════════════════════

  async function hashRanges(bytes, ranges, hashAlg) {
    // Concatenate all selected ranges into one buffer, then hash.
    // Returns { rawBytes, digest } so callers can pass rawBytes to
    // crypto.subtle.verify() (which hashes internally) while still
    // having the computed digest available for debug/display.
    let totalLen = 0;
    for (const [s, e] of ranges) totalLen += e - s;

    const rawBytes = new Uint8Array(totalLen);
    let off = 0;
    for (const [s, e] of ranges) {
      rawBytes.set(bytes.subarray(s, e), off);
      off += e - s;
    }
    const digest = new Uint8Array(await crypto.subtle.digest(hashAlg, rawBytes));
    return { rawBytes, digest };
  }

  /**
   * Compute the double-digest if id= or a timestamp is present.
   * (Mirrors SealDoubleDigest())
   *
   * If date or userid exist:
   *   preImage  = date: userid: primaryDigest   (raw bytes)
   *   newDigest = hash(preImage)
   *
   * Returns { verifyInput, digest }:
   *   verifyInput – the raw bytes that must be passed to crypto.subtle.verify()
   *                 (the API hashes internally, so we must NOT pre-hash this)
   *   digest      – the computed digest (for debug / display only)
   *
   * When there is no double-digest, verifyInput is the primaryRawBytes
   * (the concatenated file ranges) and digest is the primaryDigest.
   */
  async function doubleDigest(primaryRawBytes, primaryDigest, hashAlg, sigdate, userid) {
    if (!sigdate && !userid) {
      // No double-digest: verify() will hash primaryRawBytes itself.
      return { verifyInput: primaryRawBytes, digest: primaryDigest };
    }

    // Build pre-image: sigdate ":" userid ":" primaryDigest-bytes
    const parts = [];
    if (sigdate) { parts.push(enc.encode(sigdate)); parts.push(enc.encode(':')); }
    if (userid)  { parts.push(enc.encode(userid));  parts.push(enc.encode(':')); }
    parts.push(primaryDigest); // first digest as raw bytes

    let len = 0;
    for (const p of parts) len += p.length;
    const preImage = new Uint8Array(len);
    let o = 0;
    for (const p of parts) { preImage.set(p, o); o += p.length; }

    const d2 = new Uint8Array(await crypto.subtle.digest(hashAlg, preImage));
    // verifyInput is the pre-image: crypto.subtle.verify() will hash it → d2
    return { verifyInput: preImage, digest: d2 };
  }

  // ═══════════════════════════════════════════════════════════════
  // Cryptographic verification  (mirrors _SealValidateDigest())
  //
  // The public key (from DNS p=) is a base64-encoded DER SPKI blob.
  // SubtleCrypto.importKey with 'spki' handles RSA and EC identically.
  //
  // IMPORTANT: crypto.subtle.verify() hashes the message internally.
  // It must receive the raw pre-image bytes, NOT a pre-computed digest.
  // This differs from OpenSSL (used in the C reference), which can accept
  // a pre-computed digest directly.
  //
  // IMPORTANT (EC): OpenSSL/SEAL produces ECDSA signatures in DER format
  // (SEQUENCE { INTEGER r, INTEGER s }).  WebCrypto ECDSA requires IEEE P1363
  // format (r || s, each zero-padded to the curve's coordinate byte length).
  // We convert DER → P1363 before calling crypto.subtle.verify().
  // ═══════════════════════════════════════════════════════════════

  /**
   * Convert a DER-encoded ECDSA signature to IEEE P1363 (raw r‖s) format.
   * DER: 30 <len> 02 <rlen> <r…> 02 <slen> <s…>
   * P1363: r and s each zero-padded to `coordLen` bytes, concatenated.
   * coordLen is 32 for P-256, 48 for P-384, 66 for P-521.
   */
  function derToP1363(derSig, coordLen) {
    const d = derSig;
    if (d[0] !== 0x30) throw new Error('ECDSA sig: expected DER SEQUENCE');
    let pos = 2; // skip 0x30 + length byte (we trust the outer length)
    // Handle long-form length (rare for ECDSA but possible)
    if (d[1] & 0x80) pos += (d[1] & 0x7f);

    if (d[pos] !== 0x02) throw new Error('ECDSA sig: expected INTEGER r');
    const rLen = d[pos + 1];
    const rBytes = d.subarray(pos + 2, pos + 2 + rLen);
    pos += 2 + rLen;

    if (d[pos] !== 0x02) throw new Error('ECDSA sig: expected INTEGER s');
    const sLen = d[pos + 1];
    const sBytes = d.subarray(pos + 2, pos + 2 + sLen);

    // DER integers are signed; a leading 0x00 is added when the high bit is
    // set.  Strip it, then left-pad to coordLen.
    function padInt(src, len) {
      // strip leading zero padding bytes
      let start = 0;
      while (start < src.length - 1 && src[start] === 0x00) start++;
      const trimmed = src.subarray(start);
      const out = new Uint8Array(len);
      if (trimmed.length > len) throw new Error('ECDSA integer too large for curve');
      out.set(trimmed, len - trimmed.length);
      return out;
    }

    const p1363 = new Uint8Array(coordLen * 2);
    p1363.set(padInt(rBytes, coordLen), 0);
    p1363.set(padInt(sBytes, coordLen), coordLen);
    return p1363;
  }

  /** Return the coordinate byte length for a named WebCrypto EC curve. */
  function ecCoordLen(curve) {
    if (curve === 'P-256') return 32;
    if (curve === 'P-384') return 48;
    if (curve === 'P-521') return 66;
    throw new Error(`Unknown EC curve: ${curve}`);
  }

  async function verifySignature(pubKeyDerBytes, sigBytes, rawMessageBytes, ka, da) {
    const kaInfo = resolveKeyAlg(ka);
    if (!kaInfo) throw new Error(`Unsupported key algorithm: ${ka}`);

    const hashAlg = mapDigestAlg(da);
    if (!hashAlg) throw new Error(`Unsupported digest algorithm: ${da}`);

    let importAlg, verifyAlg, sigForVerify;
    if (kaInfo.type === 'rsa') {
      importAlg   = { name: 'RSASSA-PKCS1-v1_5', hash: hashAlg };
      verifyAlg   = 'RSASSA-PKCS1-v1_5';
      sigForVerify = sigBytes; // RSA: use signature as-is
    } else {
      // EC: detect curve, convert DER → P1363 for WebCrypto
      const curve = detectECCurve(pubKeyDerBytes);
      importAlg   = { name: 'ECDSA', namedCurve: curve };
      verifyAlg   = { name: 'ECDSA', hash: hashAlg };
      sigForVerify = derToP1363(sigBytes, ecCoordLen(curve));
    }

    const pubKey = await crypto.subtle.importKey(
      'spki',
      pubKeyDerBytes.buffer,
      importAlg,
      false,
      ['verify']
    );

    // Pass rawMessageBytes — SubtleCrypto hashes it internally using hashAlg.
    return crypto.subtle.verify(verifyAlg, pubKey, sigForVerify, rawMessageBytes);
  }

  /**
   * Heuristically detect an EC curve from a DER SPKI structure.
   * We look for the OID bytes for P-256, P-384, P-521.
   */
  function detectECCurve(derBytes) {
    // P-256 OID: 2a 86 48 ce 3d 03 01 07
    // P-384 OID: 2b 81 04 00 22
    // P-521 OID: 2b 81 04 00 23
    const oidP256 = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const oidP384 = [0x2b, 0x81, 0x04, 0x00, 0x22];
    const oidP521 = [0x2b, 0x81, 0x04, 0x00, 0x23];

    function contains(bytes, seq) {
      return findSeq(bytes, new Uint8Array(seq)) !== -1;
    }
    if (contains(derBytes, oidP521)) return 'P-521';
    if (contains(derBytes, oidP384)) return 'P-384';
    return 'P-256'; // default
  }

  // ═══════════════════════════════════════════════════════════════
  // DNS record matching  (mirrors the loop inside SealVerify())
  //
  // Checks that seal=, ka=, uid=, kv= all match between the record
  // and the DNS TXT entry before trusting the public key.
  // ═══════════════════════════════════════════════════════════════

  function dnsRecordMatches(recFields, dnsFields) {
    // seal version must match
    const recSeal = recFields.seal || '';
    const dnsSeal = dnsFields.seal || '';
    if (!recSeal || !dnsSeal || recSeal !== dnsSeal) return false;

    // If DNS specifies ka, record must agree
    if (dnsFields.ka && dnsFields.ka !== recFields.ka) return false;

    // If DNS specifies uid, record must agree
    if (dnsFields.uid && dnsFields.uid !== recFields.uid) return false;

    // kv must match (both default to "1")
    const recKv  = recFields.kv  || '1';
    const dnsKv  = dnsFields.kv  || '1';
    if (recKv !== dnsKv) return false;

    return true;
  }

  // ═══════════════════════════════════════════════════════════════
  // Revocation check  (mirrors _SealValidateRevoke())
  // ═══════════════════════════════════════════════════════════════

  function isRevoked(sigdate, dnsFields) {
    const r = dnsFields.r;
    if (!r) return false;
    if (!r || r === '' || r === 'revoke') return true; // global revoke
    if (!sigdate) return true;
    // r= is a date string; if sigdate >= r, it's revoked
    const minLen = Math.min(sigdate.length, r.length);
    return sigdate.substring(0, minLen) >= r.substring(0, minLen);
  }

  // ═══════════════════════════════════════════════════════════════
  // Inline public-key authentication  (mirrors SealInlineAuthenticate())
  //
  // When a SEAL record has pk=, it carries its own public key.
  // We validate the signature using pk=, then check against DNS
  // for either p= (exact key match) or pkd=/pka= (key digest).
  // ═══════════════════════════════════════════════════════════════

  async function inlineAuthenticate(recFields, dnsFields) {
    const pk  = recFields.pk;
    const pkd = dnsFields.pkd;
    const pka = dnsFields.pka;

    if (!pk) return { authenticated: false, error: 'no pk= in record' };

    // Case A: exact key match in DNS
    if (dnsFields.p && dnsFields.p === pk) return { authenticated: true, error: null };

    // Case B: key digest match
    if (pkd && pka) {
      const hashAlg = mapDigestAlg(pka);
      if (!hashAlg) return { authenticated: false, error: `unknown pka: ${pka}` };
      const pkBin = b64decode(pk);
      const calc  = new Uint8Array(await crypto.subtle.digest(hashAlg, pkBin));
      // encode to base64
      let b64 = btoa(String.fromCharCode(...calc));
      if (b64 !== pkd) return { authenticated: false, error: 'pkd mismatch' };
      return { authenticated: true, error: null };
    }

    return { authenticated: false, error: 'cannot authenticate inline key' };
  }

  // ═══════════════════════════════════════════════════════════════
  // Core: validate one SEAL record  (mirrors SealVerify())
  // ═══════════════════════════════════════════════════════════════

  /**
   * @param {Uint8Array}  fileBytes
   * @param {object}      rec          – from findAllSEALRecords
   * @param {object}      prevSig      – { start, end } of previous sig value (or null)
   * @param {object}      opts
   * @returns {Promise<object>}        – result object
   */
  async function validateOneRecord(fileBytes, rec, prevSig, opts) {
    const f = rec.fields;
    const warnings = [];
    const result = {
      valid:     false, // crypto validated
      auth:      false, // signature authenticated
      revoked:   false,
      domain:    f.d || '(unknown)',
      keyAlg:    f.ka || 'rsa',
      sigFormat: f.sf || 'base64',
      timestamp: null,
      error:     null,
      warnings,
      fields:    f,
    };

    const fileLen    = fileBytes.length;
    const sigValStart = rec.rawSigStart; // absolute
    const sigValEnd   = rec.rawSigEnd;  // absolute
    if (sigValStart === -1) {
      result.error = 'SEAL record has no signature (s=) field';
      return result;
    }
    const prevStart   = prevSig ? prevSig.start : 0;
    const prevEnd     = prevSig ? prevSig.end   : 0;

    // 1. ── Prepend/insertion attack warnings  ────────────────────
    const bSpec = f.b || '';
    if (!bSpec.includes('F') && !bSpec.includes('P')) {
      warnings.push('SEAL record does not cover start of file — vulnerable to prepend attack');
    }
    if (prevSig && !bSpec.includes('P') && !bSpec.includes('F')) {
      warnings.push('SEAL record does not cover previous signature — vulnerable to insertion attack');
    }

    // 2. ── Decode the signature  ─────────────────────────────────
    const { sigBytes, timestamp, error: sigErr } = decodeSig(f.s, f.sf);
    if (sigErr) { result.error = sigErr; return result; }
    if (!sigBytes || sigBytes.length === 0) {
      result.error = 'empty signature'; return result;
    }
    result.timestamp = timestamp;

    // 3. ── Compute byte ranges  ──────────────────────────────────
    const { ranges, error: rangeErr } = computeByteRanges(
      f.b || '~S,s~', fileLen,
      sigValStart, sigValEnd,
      prevStart, prevEnd
    );
    if (rangeErr) { result.error = rangeErr; return result; }
    if (!ranges || ranges.length === 0) {
      result.error = 'no bytes to hash (empty range)'; return result;
    }

    // Convert range (f.b) to bytes and text
    f.byteRanges = ranges.map(r => `${r[0]}-${r[1]-1}`).join(', ');
    f.sigRange = `${sigValStart}-${sigValEnd-1}`;
    {
    const ra = f.b.split(",");
    const rs = ra.map(r => r.split('~')[0]).join(',');
    const re = ra.map(r => r.split('~')[1]).join(',');
    f.byteDesc = "";
    if (rs.includes('F')) { f.byteDesc = 'Start of file'; }
    else if (rs.includes('P')) { f.byteDesc = 'Start of previous signature'; }
    else if (rs.includes('p')) { f.byteDesc = 'End of previous signature'; }
    else if (rs.includes('S')) { f.byteDesc = 'Start of signature'; }
    else if (rs.includes('s')) { f.byteDesc = 'End of signature'; }
    else if (rs.includes('f')) { f.byteDesc = 'End of file'; }
    else { f.byteDesc = 'Absolute offset'; }
    f.byteDesc += " to ";
    if (re.includes('f')) { f.byteDesc += 'end of file'; }
    else if (re.includes('s')) { f.byteDesc += 'end of signature'; }
    else if (re.includes('S')) { f.byteDesc += 'start of signature'; }
    else if (re.includes('p')) { f.byteDesc += 'end of previous signature'; }
    else if (re.includes('P')) { f.byteDesc += 'start of previous signature'; }
    else if (re.includes('F')) { f.byteDesc += 'start of file'; }
    else { f.byteDesc = 'Absolute offset'; }

    // Verify the end-of-file coverage
    const lastRange = ranges[ranges.length - 1];
    if (lastRange[1] < fileLen) {
      f.byteDesc += '; SEAL record does not finalize the file, data may be appended';
      }
    }

    // 4. ── Primary digest  ───────────────────────────────────────
    const da = f.da || 'sha256';
    const hashAlg = mapDigestAlg(da);
    if (!hashAlg) { result.error = `Unknown digest algorithm: ${da}`; return result; }

    const { rawBytes: primaryRawBytes, digest: primaryDigest } =
      await hashRanges(fileBytes, ranges, hashAlg);

    // 5. ── Double digest  (if date or id present)  ───────────────
    //    verifyInput = raw bytes to hand to crypto.subtle.verify()
    //    digest      = the final computed hash (for debug display only)
    const { verifyInput, digest } =
      await doubleDigest(primaryRawBytes, primaryDigest, hashAlg, timestamp, f.id || null);

    // Expose the computed digest on the result for debugging.
    // (hex string, lower-case)
    result.debugDigest = Array.from(digest).map(b => b.toString(16).padStart(2,'0')).join('');

    // 6. ── Inline public key path  ───────────────────────────────
    let isInline = false;
    let inlineVerified = false;
    let pubKeyBin = null;

    if (f.pk) {
      isInline = true;
      pubKeyBin = b64decode(f.pk);
      }

    // 7. ── DNS lookup and matching  ──────────────────────────────
    if (!f.d) { result.error = 'No domain (d=) in SEAL record'; return result; }

    const dnsName = `${f.d}`;

    let dnsRecords = [];
    if (opts && opts.dnsOverride) {
      // dnsOverride can be: string (raw TXT) or object (pre-parsed fields)
      const ov = opts.dnsOverride;
      const parsed = typeof ov === 'string' ? parseDNSTXT(ov) : ov;
      if (parsed) dnsRecords = [parsed];
    } else if (opts && opts.dnsOverrideMap && opts.dnsOverrideMap[f.d]) {
      const parsed = parseDNSTXT(opts.dnsOverrideMap[f.d]);
      if (parsed) dnsRecords = [parsed];
    } else {
      try { dnsRecords = await dnsLookup(dnsName); }
      catch (e) { result.error = `DNS lookup failed: ${e.message}`; return result; }
    }

    if (!dnsRecords || dnsRecords.length === 0) {
      result.error = `No SEAL DNS record found for ${dnsName}`;
      return result;
    }

    // Try each DNS record until one validates
    let globalRevoke = null;
    let globalRevokeDns = null;
    let lastError    = null;
    let lastErrorDns = null;

    // Check every DNS record
    for (const dns of dnsRecords) {
      // Check field compatibility (seal=, ka=, uid=, kv=)
      if (!dnsRecordMatches(f, dns)) continue;

      // Check for global revoke (p= is "revoke" or absent)
      const dnsKey = dns.p || dns.pkd;
      if (!dnsKey || dnsKey === 'revoke') {
        globalRevoke = 'domain default revoke';
        globalRevokeDns = dns;
        continue;
      }

      // Check r= revocation BEFORE attempting crypto — a DNS record with a
      // real public key AND r=revoke means the key (and all sigs by it) are
      // revoked regardless of whether the signature itself verifies.
      if (isRevoked(timestamp, dns)) {
        result.revoked    = true;
        result.error      = 'public key revoked';
        result.matchedDNS = dns;
        return result;
      }

      // Figure out which public key to use based on inline status

      // Inline path: authenticate the inline public key against DNS
      if (isInline) {
        result.auth = false;
        if (dns.p === f.pk) {
          // Exact key match in DNS
          result.auth = true;
          result.matchedDNS = dns;
          }
        else {
          // Try pkd/pka digest authentication
          const { authenticated } = await inlineAuthenticate(f, dns);
          if (authenticated) {
            result.auth = true;
            }
          }
        } // if isInline
      else { // Not inline
        if (!dns.p && dns.pkd) { continue; } // skip inline-only TXT entries
        if (dns._pBin) { pubKeyBin = dns._pBin; }
        else { pubKeyBin = null; }
        } // if not isInline

      //////////////////////////////////////////
      // Verify signature against DNS public key
      if (!pubKeyBin) {
        lastError = 'DNS record has no usable public key';
        lastErrorDns = dns;
        continue;
        }

      let ok = false;
      if (opts && opts.verifyOverride) { ok=true; }
      else {
        try {
            ok = await verifySignature(pubKeyBin, sigBytes, verifyInput, f.ka || 'rsa', da);
          } catch (e) {
            lastError = `Verification error: ${e.message}`;
            lastErrorDns = dns;
            continue;
          }
        }

      if (!ok) {
        lastError = 'signature mismatch';
        lastErrorDns = dns;
        continue;
        }

      // ✓ Valid!
      result.valid      = true;
      if (!isInline) { result.auth = true; }
      result.error      = null;
      result.matchedDNS = dns;
      return result;
    }

    // No DNS record matched
    if (globalRevoke) {
      result.revoked = true;
      result.error   = globalRevoke;
      result.matchedDNS = globalRevokeDns;
    } else if (!result.valid) {
      result.error = lastError || 'could not validate against any DNS record';
      result.matchedDNS = lastErrorDns;
    }
    return result;
  }


  // ═══════════════════════════════════════════════════════════════
  // Format-aware SEAL record extraction
  //
  // Each scanner mirrors the corresponding Seal_XXX() function in the C code.
  // Every scanner returns an array of ScanResult objects:
  //   { bytes, records }
  //   where `bytes` is the Uint8Array slice that defines the coordinate space
  //   for this SEAL scope (i.e. what F=0 and f=fileLen mean for these records),
  //   and `records` is an array of parsed SEAL records (from parseSEALRecord /
  //   findAllSEALRecords) with rawSigStart/rawSigEnd absolute within `bytes`.
  //
  // The critical guarantee: records found inside a nested scope (JPEG thumbnail,
  // individual ZIP entry, EXIF block) use the nested bytes as their coordinate
  // space, so their b= ranges resolve correctly within that sub-file rather than
  // against the outer file.
  // ═══════════════════════════════════════════════════════════════

  /**
   * Scan a byte window [start, end) for SEAL records using the generic
   * text-search.  All returned records have rawSigStart/rawSigEnd
   * absolute within `allBytes` (the file-level buffer).
   * Filters out records whose rawSigStart is -1 (no s= field).
   */
  function scanBlock(allBytes, start, end) {
    const slice = allBytes.subarray(start, end);
    const recs  = findAllSEALRecords(slice);
    // Translate positions back to allBytes-absolute
    const out = [];
    for (const r of recs) {
      if (r.rawSigStart === -1) continue; // no s= value — skip
      out.push({
        fields:       r.fields,
        recStart:     r.recStart  + start,
        recEnd:       r.recEnd,          // relative
        rawSigStart:  r.rawSigStart + start,
        rawSigEnd:    r.rawSigEnd   + start,
      });
    }
    return out;
  }

  /**
   * Scan EXIF data for SEAL records.
   * Mirrors Seal_Exif(): only looks at top-level IFD0, tag 0xcea1
   * (and also UserComment 0x9286 and Comment 0xfffe).
   * `exifOffset` and `exifSize` are absolute in `allBytes`.
   */
  function scanExif(allBytes, exifOffset, exifSize) {
    if (exifOffset + exifSize > allBytes.length) return [];
    const b = allBytes;
    const base = exifOffset;

    // Read TIFF header within the EXIF block
    if (exifSize < 8 + 2 + 12) return [];
    let endian;
    if (b[base]===0x49 && b[base+1]===0x49 && b[base+2]===0x2A) endian = 'le';
    else if (b[base]===0x4D && b[base+1]===0x4D && b[base+3]===0x2A) endian = 'be';
    else return [];

    const r16 = endian === 'le' ? readLE16 : readBE16;
    const r32 = endian === 'le' ? readLE32 : readBE32;

    let ifdOff = r32(b, base + 4);
    if (ifdOff < 8 || base + ifdOff + 2 + 12 > allBytes.length) return [];

    const count = r16(b, base + ifdOff);
    ifdOff += 2;

    const out = [];
    for (let e = 0; e < count; e++) {
      const eoff = base + ifdOff + e * 12;
      if (eoff + 12 > allBytes.length) break;
      const tag      = r16(b, eoff);
      const type     = r16(b, eoff + 2);
      const dataSize = r32(b, eoff + 4);
      const dataOff  = r32(b, eoff + 8);

      // Only byte/ascii/undefined types (1, 2, 6, 7)
      if (type !== 1 && type !== 2 && type !== 6 && type !== 7) continue;
      if (dataSize <= 4) continue; // too small for a SEAL record
      if (base + dataOff + dataSize > allBytes.length) continue;

      // Only these tags
      if (tag !== 0xcea1 && tag !== 0x9286 && tag !== 0xfffe) continue;

      const recs = scanBlock(allBytes, base + dataOff, base + dataOff + dataSize);
      out.push(...recs);
    }
    return out;
  }

  // ── JPEG ────────────────────────────────────────────────────────
  // Mirrors Seal_JPEG():
  //   - Walk APP blocks (0xffe0–0xffef) and comment (0xfffe)
  //   - Skip continuation blocks (same tag as previous)
  //   - Skip known embedded-media labels (JFIF, Exif thumbnail, ICC_PROFILE…)
  //   - Give EXIF (Exif\0\0) special processing via scanExif()
  //   - Stop at 0xffda (SOS)  — do NOT scan into the image stream
  //   - Skip MPF (nested images after 0xffd9) entirely

  // Labels to skip (they may contain nested media)
  const JPEG_SKIP_LABELS = [
    'JP ', 'JPN ', 'HPQ-', 'DP2 ', 'PIC ', 'AROT ', 'JFIF ', 'JFXX ',
    'HPSC ', 'H3X0 ', 'FPXR ', 'MOTO ', 'XMTH ', 'Adobe ', 'Ducky ',
    'AJPEG ', 'SCRNAIL', 'MMIMETA', 'Ocad$Rev', 'Qualcomm', 'ssuniqueid',
    'HPQ-Capture', 'ICC_PROFILE ', 'Photoshop 3.0 ', 'GenaPhotoStamperd',
  ];

  function scanJPEG(bytes) {
    if (bytes.length < 4) return [];
    // Quick magic check
    if (bytes[0] !== 0xFF || bytes[1] !== 0xD8) return [];

    const out = [];
    let offset = 2;
    let prevTag = 0xFFD8;

    while (offset + 4 <= bytes.length) {
      // JPEG spec: skip non-tag bytes (corruption tolerance)
      const tag = readBE16(bytes, offset);
      if ((tag & 0xFFC0) !== 0xFFC0) { offset++; continue; }

      if (tag === 0xFFD9) break; // end of image — stop
      if (tag === 0xFFDA) break; // SOS (start of stream) — stop

      const blockSize = readBE16(bytes, offset + 2);
      if (blockSize < 2 || offset + 2 + blockSize > bytes.length) break;

      const dataStart = offset + 4;         // after tag + length
      const dataLen   = blockSize - 2;      // length field includes itself

      if ((tag & 0xFFF0) === 0xFFE0) {
        // APP block: ffe0–ffef
        // Skip continuation of same APP type
        if (tag === prevTag) { offset += 2 + blockSize; prevTag = tag; continue; }

        // MPF: skip — it references post-ffd9 images which are self-contained
        if (dataLen > 4 && matchAt(bytes, dataStart, 'MPF ')) {
          offset += 2 + blockSize; prevTag = tag; continue;
        }

        // EXIF: special IFD-aware scan
        if (dataLen > 6 && matchAt(bytes, dataStart, 'Exif  ')) {
          const exifStart = dataStart + 6;
          const exifLen   = dataLen   - 6;
          out.push(...scanExif(bytes, exifStart, exifLen));
          offset += 2 + blockSize; prevTag = tag; continue;
        }

        // Skip known embedded-media labels
        let skipIt = false;
        for (const lbl of JPEG_SKIP_LABELS) {
          if (dataLen > lbl.length && matchAt(bytes, dataStart, lbl)) {
            skipIt = true; break;
          }
        }
        if (skipIt) { offset += 2 + blockSize; prevTag = tag; continue; }

        // Generic APP block — scan for SEAL
        out.push(...scanBlock(bytes, dataStart, dataStart + dataLen));

      } else if (tag === 0xFFFE) {
        // Comment block
        out.push(...scanBlock(bytes, dataStart, dataStart + dataLen));
      }

      offset += 2 + blockSize;
      prevTag = tag;
    }
    return out;
  }

  // ── PNG ──────────────────────────────────────────────────────────
  // Mirrors Seal_PNG():
  //   Walk chunks; scan text/itxt/seal chunks and exif chunks.
  //   Stop at IEND.  Never scan zTXt (compressed).
  function scanPNG(bytes) {
    if (bytes.length < 12) return [];
    if (!matchAt(bytes, 0, '\x89PNG\r\n\x1a\n')) return [];

    const out = [];
    let offset = 8; // skip 8-byte PNG header

    while (offset + 12 <= bytes.length) {
      const chunkSize = readBE32(bytes, offset);
      const fourcc    = decodeStr(bytes, offset + 4, offset + 8);

      if (offset + 12 + chunkSize > bytes.length) break;

      if (fourcc === 'IEND') break;

      const dataStart = offset + 8;
      const dataEnd   = offset + 8 + chunkSize;

      if (fourcc.toLowerCase() === 'text' ||
          fourcc.toLowerCase() === 'itxt' ||
          fourcc.toLowerCase() === 'seal') {
        out.push(...scanBlock(bytes, dataStart, dataEnd));
      } else if (fourcc.toLowerCase() === 'exif') {
        out.push(...scanExif(bytes, dataStart, chunkSize));
      }

      offset += 12 + chunkSize; // size + FourCC + data + CRC
    }
    return out;
  }

  // ── GIF ───────────────────────────────────────────────────────────
  // Mirrors _SealWalkGIF():
  //   Walk extension blocks (0x21); scan application extensions (0x21 0xff).
  //   Stop at trailer (0x3b) or image descriptor (0x2c).
  function scanGIF(bytes) {
    if (bytes.length < 16) return [];
    if (!matchAt(bytes, 0, 'GIF87a') && !matchAt(bytes, 0, 'GIF89a')) return [];

    const out = [];
    let offset = 10;

    // Skip Global Color Table
    if (bytes[10] & 0x80) {
      const ctSize = 3 * (1 << ((bytes[10] & 0x07) + 1));
      offset = 13 + ctSize;
    }

    while (offset < bytes.length) {
      const tag = bytes[offset++];
      if (offset >= bytes.length) break;

      if (tag === 0x3B) break; // trailer
      if (tag === 0x00) continue;

      if (tag === 0x2C) {
        // Image descriptor — skip it (it contains image data, not metadata)
        offset += 8;
        if (offset >= bytes.length) break;
        if (bytes[offset] & 0x80) {
          const lct = 3 * (1 << ((bytes[offset] & 0x07) + 1));
          offset += lct + 1;
        } else offset++;
        if (offset >= bytes.length) break;
        // Skip LZW image data
        let subLen = bytes[offset++];
        while (subLen > 0 && offset < bytes.length) {
          offset += subLen;
          subLen = offset < bytes.length ? bytes[offset++] : 0;
        }
        continue;
      }

      if (tag === 0x21) {
        const subtag      = bytes[offset++];
        const blockStart  = offset;
        // Consume sub-blocks
        let subLen = bytes[offset++];
        while (subLen > 0 && offset < bytes.length) {
          offset += subLen;
          subLen = offset < bytes.length ? bytes[offset++] : 0;
        }
        // Application extension (0xff) may contain SEAL
        if (subtag === 0xFF) {
          out.push(...scanBlock(bytes, blockStart, offset));
        }
      }
    }
    return out;
  }

  // ── RIFF (WAV, AVI, WebP) ─────────────────────────────────────────
  // Mirrors _RIFFwalk():
  //   Walk RIFF and LIST(INFO) chunks; scan any chunk in _RIFFvalidate list,
  //   plus EXiF chunks.  Skip everything else.
  const RIFF_SCAN_FOURCC = new Set([
    'SEAL', 'XMP ', 'IARL','IART','ICDS','ICMS','ICMT','ICOP','ICRD','ICRP',
    'IDIM','IDIT','IDPI','IEDT','IENG','IGNR','IKEY','ILGT','IMED','IMUS',
    'INAM','IPDS','IPLT','IPRD','IPRO','ISBJ','ISFT','ISGN','ISHP','ISMP',
    'ISRC','ISRF','ISTD','ISTR','ITCH','IWEB','IWRI',
  ]);

  function scanRIFF(bytes) {
    if (bytes.length < 16) return [];
    if (!matchAt(bytes, 0, 'RIFF')) return [];
    const totalSize = readLE32(bytes, 4);
    if (totalSize + 8 !== bytes.length) return []; // size mismatch

    return _riffWalk(bytes, 0, bytes.length, 0);
  }

  function _riffWalk(bytes, posStart, posEnd, depth) {
    const out = [];
    while (posStart + 8 < posEnd) {
      const fourcc = decodeStr(bytes, posStart, posStart + 4);
      const size   = readLE32(bytes, posStart + 4);
      if (posStart + 8 + size > posEnd) break;

      if (depth < 1 && fourcc === 'RIFF') {
        if (size > 4)
          out.push(..._riffWalk(bytes, posStart + 12, posStart + 12 + size, depth + 1));
      } else if (depth < 2 && fourcc === 'LIST') {
        if (size > 4) {
          const listType = decodeStr(bytes, posStart + 8, posStart + 12);
          if (listType === 'INFO')
            out.push(..._riffWalk(bytes, posStart + 12, posStart + 12 + size, depth + 1));
        }
      } else if (fourcc === 'EXiF') {
        out.push(...scanExif(bytes, posStart + 8, size));
      } else if (RIFF_SCAN_FOURCC.has(fourcc)) {
        out.push(...scanBlock(bytes, posStart + 8, posStart + 8 + size));
      }

      // RIFF pads to 16-bit alignment
      const padded = size % 2 ? size + 1 : size;
      posStart += 8 + padded;
    }
    return out;
  }

  // ── ISO-BMFF (MP4, MOV, HEIC, AVIF, …) ───────────────────────────
  // Mirrors _BMFFwalk():
  //   Walk top-level atoms; scan atoms listed in BMFFatoms[] ('s' type).
  //   Give Exif atoms ('e' type) EXIF-aware scanning.
  //   Recursion is disabled in the C code for BMFF (too complex).
  const BMFF_SCAN_ATOMS = new Set(['SEAL','name','mdta','keys','mime','xml ','XMP_']);
  const BMFF_EXIF_ATOMS = new Set(['Exif']);

  function scanBMFF(bytes) {
    if (bytes.length < 16) return [];
    if (!matchAt(bytes, 4, 'ftyp')) return [];
    return _bmffWalk(bytes, 0, bytes.length);
  }

  function _bmffWalk(bytes, dataStart, dataEnd) {
    const out = [];
    while (dataStart + 8 <= dataEnd) {
      let atomLen = readBE32(bytes, dataStart);
      if (atomLen === 0) { dataStart += 4; continue; }
      let headerSize = 8;

      // Extended (64-bit) length
      if (atomLen === 1) {
        if (dataStart + 16 > dataEnd) break;
        // readBE64 approximation (files >4GB unlikely in browser context)
        const hi = readBE32(bytes, dataStart + 8);
        const lo = readBE32(bytes, dataStart + 12);
        atomLen = hi * 0x100000000 + lo;
        headerSize = 16;
      }

      if (dataStart + atomLen > dataEnd) break;

      const fourcc = decodeStr(bytes, dataStart + 4, dataStart + 8);

      if (BMFF_SCAN_ATOMS.has(fourcc)) {
        out.push(...scanBlock(bytes, dataStart, dataStart + atomLen));
      } else if (BMFF_EXIF_ATOMS.has(fourcc)) {
        out.push(...scanExif(bytes, dataStart, atomLen));
      }

      dataStart += atomLen;
    }
    return out;
  }

  // ── TIFF (+ DNG, CR2, NEF, ARW, …) ──────────────────────────────
  // Mirrors _TIFFwalk():
  //   Walk the top-level IFD chain only.
  //   Look for tag 0xcea1 with byte/ascii types.
  //   Do NOT recurse into nested IFDs.
  function scanTIFF(bytes) {
    if (bytes.length < 8) return [];
    let endian;
    if (bytes[0]===0x49 && bytes[1]===0x49 && bytes[2]===0x2A) endian='le';
    else if (bytes[0]===0x4D && bytes[1]===0x4D && bytes[3]===0x2A) endian='be';
    else return [];

    const r16 = endian === 'le' ? readLE16 : readBE16;
    const r32 = endian === 'le' ? readLE32 : readBE32;

    const out = [];
    let ifdOff = r32(bytes, 4);

    while (ifdOff > 0 && ifdOff + 6 < bytes.length) {
      const count = r16(bytes, ifdOff);
      ifdOff += 2;

      for (let e = 0; e < count; e++) {
        const eoff = ifdOff + e * 12;
        if (eoff + 12 > bytes.length) break;

        const tag     = r16(bytes, eoff);
        const type    = r16(bytes, eoff + 2);
        const dcount  = r32(bytes, eoff + 4);
        const doffset = r32(bytes, eoff + 8);

        if (tag !== 0xcea1) continue;
        // Only byte/ascii/signed-byte types
        if (type !== 1 && type !== 2 && type !== 6) continue;
        if (dcount <= 4) continue; // inline, too small
        if (doffset + dcount > bytes.length) continue;

        out.push(...scanBlock(bytes, doffset, doffset + dcount));
      }

      // Next IFD pointer (4 bytes after the last entry)
      const nextOff = ifdOff + count * 12;
      if (nextOff + 4 > bytes.length) break;
      const next = r32(bytes, nextOff);
      if (next <= ifdOff) break; // no loops
      ifdOff = next;
    }
    return out;
  }

  // ── Matroska (MKV, WebM, MKA) ─────────────────────────────────────
  // Mirrors _Matroskawalk():
  //   Walk EBML elements; scan the SEAL element (tag 0x5345414C).
  function scanMatroska(bytes) {
    if (bytes.length < 4) return [];
    if (bytes[0]!==0x1A||bytes[1]!==0x45||bytes[2]!==0xDF||bytes[3]!==0xA3) return [];

    const out = [];
    let offset = 0;

    function readEBML(off) {
      if (off >= bytes.length) return { val: -1, end: off };
      const b = bytes[off];
      if (b === 0) return { val: -1, end: off + 1 };
      let numBytes = 1;
      for (let i = 7; i >= 0; i--) {
        if (b & (1 << i)) { numBytes = 8 - i; break; }
      }
      let val = b & ~(0xFF << (8 - numBytes));
      for (let i = 1; i < numBytes; i++) {
        if (off + i >= bytes.length) return { val: -1, end: off + i };
        val = (val * 256) + bytes[off + i];
      }
      return { val, end: off + numBytes };
    }

    while (offset < bytes.length) {
      const tagR = readEBML(offset);
      if (tagR.val === -1) break;
      offset = tagR.end;
      const lenR = readEBML(offset);
      if (lenR.val === -1) break;
      offset = lenR.end;
      const iLen = lenR.val;
      if (offset + iLen > bytes.length) break;

      if (tagR.val === 0x5345414C) { // SEAL tag
        out.push(...scanBlock(bytes, offset, offset + iLen));
      }
      offset += iLen;
    }
    return out;
  }

  // ── PDF ────────────────────────────────────────────────────────────
  // Mirrors _PDFwalk():
  //   Scan for SEAL records OUTSIDE objects (between endobj and obj).
  //   PDF SEAL records appear as: %<seal .../>  at the top level.
  function scanPDF(bytes) {
    if (bytes.length < 20) return [];
    if (!matchAt(bytes, 0, '%PDF')) return [];

    // Quick check for %%EOF at end (with trailing whitespace)
    let eof = bytes.length - 1;
    while (eof > 20 && (bytes[eof] === 0x0A || bytes[eof] === 0x0D || bytes[eof] === 0x20)) eof--;
    if (!matchAt(bytes, eof - 4, '%%EOF')) return [];

    const out = [];
    const td2 = new TextDecoder('latin1'); // PDF can contain binary
    let pos = 0;
    let objDepth = 0;

    while (pos < bytes.length) {
      // Detect "obj" keyword (preceded by whitespace): enter object
      if (pos + 5 < bytes.length &&
          (bytes[pos] === 0x20 || bytes[pos] === 0x09 ||
           bytes[pos] === 0x0A || bytes[pos] === 0x0D) &&
          bytes[pos+1]===0x6F && bytes[pos+2]===0x62 && bytes[pos+3]===0x6A &&
          (bytes[pos+4]===0x20||bytes[pos+4]===0x09||bytes[pos+4]===0x0A||bytes[pos+4]===0x0D)) {
        objDepth++;
        pos += 5;
        continue;
      }
      // Detect "endobj"
      if (pos + 7 <= bytes.length &&
          bytes[pos]===0x65&&bytes[pos+1]===0x6E&&bytes[pos+2]===0x64&&
          bytes[pos+3]===0x6F&&bytes[pos+4]===0x62&&bytes[pos+5]===0x6A &&
          (bytes[pos+6]===0x20||bytes[pos+6]===0x09||bytes[pos+6]===0x0A||bytes[pos+6]===0x0D)) {
        if (objDepth > 0) objDepth--;
        pos += 7;
        continue;
      }
      // Outside objects, look for %<seal
      if (objDepth === 0 && pos + 7 < bytes.length &&
          bytes[pos]===0x25 && bytes[pos+1]===0x3C && // '%<'
          bytes[pos+2]===0x73&&bytes[pos+3]===0x65&&bytes[pos+4]===0x61&&
          bytes[pos+5]===0x6C&&bytes[pos+6]===0x20) { // 'seal '
        // Find end of line
        let pend = pos + 1;
        while (pend < bytes.length && bytes[pend] !== 0x0A && bytes[pend] !== 0x0D) pend++;
        // Pass the block starting one byte in (skip the '%')
        out.push(...scanBlock(bytes, pos + 1, pend));
        pos = pend;
        continue;
      }
      pos++;
    }
    return out;
  }

  // ── ZIP ────────────────────────────────────────────────────────────
  // Mirrors Seal_Zip():
  //   Scan backwards for each EOCD. For each zip found:
  //     - The SEAL scope is [start_of_local_headers .. end_of_eocd_comment]
  //     - The SEAL record lives in the EOCD archive comment field
  //   Multiple embedded zips are handled by scanning for each EOCD.
  function scanZIP(bytes) {
    if (bytes.length < 22) return [];

    const out = [];
    // Search backwards for EOCD signatures (50 4b 05 06)
    let scanEnd = bytes.length;

    while (scanEnd >= 22) {
      const eocd = findEOCD(bytes, scanEnd);
      if (eocd < 0) break;

      // Parse EOCD
      const commentLen = readLE16(bytes, eocd + 20);
      const commentOff = eocd + 22;
      if (commentOff + commentLen > bytes.length) { scanEnd = eocd - 1; continue; }

      const cdSize   = readLE32(bytes, eocd + 12);
      const cdOffset = readLE32(bytes, eocd + 16);

      // Check for zip64 (all 0xffffffff)
      let zipStart;
      if (cdSize === 0xFFFFFFFF || cdOffset === 0xFFFFFFFF) {
        // zip64: find the Zip64 EOCD locator just before eocd
        if (eocd < 20 + 56) { scanEnd = eocd - 1; continue; }
        if (!matchAt(bytes, eocd - 20, '\x50\x4b\x06\x07') ||
            !matchAt(bytes, eocd - 20 - 56, '\x50\x4b\x06\x06')) {
          scanEnd = eocd - 1; continue;
        }
        // Extract start from zip64 eocd
        const z64off = readLE32(bytes, eocd - 20 + 8); // simplified (lower 32 bits)
        zipStart = (eocd - 20 - 56) - z64off;
      } else {
        // Regular zip
        if (cdSize + cdOffset > eocd) { scanEnd = eocd - 1; continue; } // corrupt
        zipStart = eocd - cdSize - cdOffset;
      }

      if (zipStart < 0 || zipStart >= bytes.length) { scanEnd = eocd - 1; continue; }

      // The SEAL signature lives in the EOCD comment
      // The coordinate space for this zip is [zipStart .. commentOff + commentLen)
      const zipEnd = commentOff + commentLen;
      const zipBytes = bytes.subarray(zipStart, zipEnd);

      // Scan the comment field — positions must be translated back to zipBytes-local
      const commentLocalStart = commentOff - zipStart;
      const commentLocalEnd   = commentLocalStart + commentLen;

      const recs = findAllSEALRecords(zipBytes.subarray(commentLocalStart, commentLocalEnd));
      for (const r of recs) {
        if (r.rawSigStart === -1) continue;
        out.push({
          bytes:        zipBytes,                          // ← coordinate space for this zip
          fields:       r.fields,
          recStart:     r.recStart  + commentLocalStart,
          recEnd:       r.recEnd,
          rawSigStart:  r.rawSigStart + commentLocalStart,
          rawSigEnd:    r.rawSigEnd   + commentLocalStart,
        });
      }

      scanEnd = eocd - 1;
    }
    return out;
  }

  function findEOCD(bytes, searchEnd) {
    // Search backwards for 50 4b 05 06
    for (let i = Math.min(searchEnd - 22, bytes.length - 22); i >= 0; i--) {
      if (bytes[i]===0x50 && bytes[i+1]===0x4B && bytes[i+2]===0x05 && bytes[i+3]===0x06)
        return i;
    }
    return -1;
  }

  // ── Text / XML / SVG / HTML ──────────────────────────────────────
  // Mirrors Seal_Text(): scan the entire file as a text blob.
  function scanText(bytes) {
    return scanBlock(bytes, 0, bytes.length);
  }

  // ── MP3 + ID3 ────────────────────────────────────────────────────
  // Mirrors Seal_MPEG() / _SealWalkMPEG():
  // Scan ID3v2 tags (at the front) and any APP blocks.
  // For simplicity, scan text frames (T*, COM, COMM) inside ID3v2.
  function scanMP3(bytes) {
    if (bytes.length < 10) return [];
    // ID3v2 header: "ID3" + version + flags + syncsafe size
    if (!matchAt(bytes, 0, 'ID3')) return [];

    const flags   = bytes[5];
    const sz      = ((bytes[6]&0x7F)<<21)|((bytes[7]&0x7F)<<14)|
                    ((bytes[8]&0x7F)<<7)|(bytes[9]&0x7F);
    const id3End  = 10 + sz;

    // Scan the entire ID3 tag for SEAL records
    return scanBlock(bytes, 0, Math.min(id3End, bytes.length));
  }

  // ── DICOM ────────────────────────────────────────────────────────
  // SEAL in DICOM lives in the preamble or in (0009,0010) private tag area.
  // For validation purposes, scan the full file as text (like Seal_Text does
  // for unknown formats), but only outside the pixel-data element (7FE0,0010).
  function scanDICOM(bytes) {
    if (bytes.length < 132) return [];
    if (!matchAt(bytes, 128, 'DICM')) return [];
    // Scan header preamble (0..128) and all non-pixel-data content
    // Simple approach: scan the whole file — pixel data will not contain <seal
    return scanBlock(bytes, 0, bytes.length);
  }

  // ─── Main format dispatcher ────────────────────────────────────────
  /**
   * Dispatch to the appropriate format-aware scanner.
   * Returns an array of objects:
   *   { bytes, fields, recStart, recEnd, rawSigStart, rawSigEnd }
   * where `bytes` is the coordinate space for b= range computation
   * (either the whole file, or a sub-file for ZIP entries).
   */
  function scanByFormat(bytes) {
    const fmt = detectFormat(bytes);

    let recs;
    switch (fmt) {
      case 'jpeg':     recs = scanJPEG(bytes);     break;
      case 'png':      recs = scanPNG(bytes);      break;
      case 'gif':      recs = scanGIF(bytes);      break;
      case 'riff':     recs = scanRIFF(bytes);     break;
      case 'bmff':     recs = scanBMFF(bytes);     break;
      case 'tiff':     recs = scanTIFF(bytes);     break;
      case 'matroska': recs = scanMatroska(bytes); break;
      case 'pdf':      recs = scanPDF(bytes);      break;
      case 'zip':      recs = scanZIP(bytes);      break;
      case 'mp3':      recs = scanMP3(bytes);      break;
      case 'dicom':    recs = scanDICOM(bytes);    break;
      case 'xml':      // SVG, HTML, plain XML — fall through
      case 'text':
      default:         recs = scanText(bytes);     break;
    }

    // Attach the coordinate-space bytes if not already set (ZIP sets it per entry)
    return recs.map(r => r.bytes ? r : { ...r, bytes });
  }

  // ═══════════════════════════════════════════════════════════════
  // Top-level validation entry point
  // ═══════════════════════════════════════════════════════════════

  /**
   * Validate all SEAL records found in a file buffer.
   *
   * @param {ArrayBuffer|Uint8Array} buffer
   * @param {string}  [filename]
   * @param {object}  [opts]
   * @returns {Promise<Array>}
   */
  async function validateBuffer(buffer, filename, opts = {}) {
    const bytes = u8(buffer);
    const recs  = scanByFormat(bytes);

    if (recs.length === 0) {
      return [{
        valid: false, revoked: false,
        domain: '', keyAlg: '', sigFormat: '',
        timestamp: null, filename: filename || '(unknown)',
        error: 'No SEAL record found in file',
        warnings: [], fields: {},
      }];
    }

    const results = [];
    let prevSig = null; // tracks previous signature value position

    for (let i = 0; i < recs.length; i++) {
      const rec = recs[i];
      // rec.bytes is the coordinate space (whole file, or zip sub-file)
      const r = await validateOneRecord(rec.bytes, rec, prevSig, opts);
      r.filename    = filename || '(unknown)';
      r.recordIndex = i + 1;
      r.recordCount = recs.length;
      results.push(r);

      // Update previous-sig pointer for the next iteration
      prevSig = { start: rec.rawSigStart, end: rec.rawSigEnd };
    }

    return results;
  }

  /**
   * Fetch a URL and validate.
   *
   * @param {string} url
   * @param {object} [opts]
   * @returns {Promise<Array>}
   */
  async function validateURL(url, opts = {}) {
    const fetchOpts = {};
    if (opts.crossOrigin) fetchOpts.mode = 'cors';
    const resp = await fetch(url, fetchOpts);
    if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching ${url}`);
    const buf = await resp.arrayBuffer();
    const filename = url.split('/').pop().split('?')[0] || url;
    return validateBuffer(buf, filename, opts);
  }

  /**
   * Scan all <img> (or custom selector) elements on the current page.
   *
   * @param {object} [opts]
   * @returns {Promise<Map<string, Array>>}
   */
  async function scanPageImages(opts = {}) {
    const selector = opts.selector || 'img';
    const imgs = Array.from(document.querySelectorAll(selector));
    const resultMap = new Map();

    await Promise.allSettled(imgs.map(async (img) => {
      const src = img.currentSrc || img.src;
      if (!src || resultMap.has(src)) return;
      try {
        resultMap.set(src, await validateURL(src, opts));
      } catch (e) {
        resultMap.set(src, [{
          valid: false, revoked: false,
          domain: '', keyAlg: '', sigFormat: '',
          timestamp: null, filename: src,
          error: e.message, warnings: [], fields: {},
        }]);
      }
    }));

    return resultMap;
  }

  /**
   * Validate the image pointed to by an <img> element.
   *
   * @param {HTMLImageElement} imgEl
   * @param {object} [opts]
   * @returns {Promise<Array>}
   */
  async function validateImage(imgEl, opts = {}) {
    const src = imgEl.currentSrc || imgEl.src;
    if (!src) {
      return [{ valid: false, revoked: false, error: 'No src on image element',
                domain: '', keyAlg: '', sigFormat: '', timestamp: null,
                filename: '', warnings: [], fields: {} }];
    }
    return validateURL(src, opts);
  }

  // ═══════════════════════════════════════════════════════════════
  // File-format detection helper (informational only — the validator
  // works format-agnostically by searching for <seal …/> text)
  // ═══════════════════════════════════════════════════════════════

  function detectFormat(bytes) {
    if (bytes.length < 4) return 'unknown';
    const b = bytes;
    if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'jpeg';
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return 'png';
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return 'gif';
    if (matchAt(b, 0, '%PDF')) return 'pdf';
    if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46) return 'riff'; // WAV/AVI/WebP
    if (b.length >= 8 && matchAt(b, 4, 'ftyp')) return 'bmff'; // MP4/HEIC/AVIF/...
    if (b[0] === 0x1A && b[1] === 0x45 && b[2] === 0xDF && b[3] === 0xA3) return 'matroska';
    if ((b[0] === 0x49 && b[1] === 0x49 && b[2] === 0x2A) ||
        (b[0] === 0x4D && b[1] === 0x4D && b[2] === 0x00 && b[3] === 0x2A)) return 'tiff';
    if (b[0] === 0x50 && b[1] === 0x4B) return 'zip';
    if (b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33) return 'mp3';
    if (b.length >= 132 && matchAt(b, 128, 'DICM')) return 'dicom';
    const head = decodeStr(b, 0, Math.min(64, b.length)).trimStart();
    if (head.startsWith('<')) return 'xml';
    return 'text';
  }

  // ═══════════════════════════════════════════════════════════════
  // Public API
  // ═══════════════════════════════════════════════════════════════

  const api = {
    // Primary API
    validateBuffer,
    validateURL,
    scanPageImages,
    validateImage,

    // Utility / testing hooks
    detectFormat,
    _parseDNSTXT:        parseDNSTXT,
    _findAllSEALRecords: findAllSEALRecords,
    _scanByFormat:       scanByFormat,
    _computeByteRanges:  computeByteRanges,
    _decodeSig:          decodeSig,
  };

  root.SEAL = api;
}(typeof globalThis !== 'undefined' ? globalThis : this));

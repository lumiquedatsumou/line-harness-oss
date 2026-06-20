#!/usr/bin/env node
/**
 * Redacted-log regression guard (staged rollout).
 *
 * Fails CI if a *bare* error object is passed to console.* in an already-hardened
 * file without going through redactForLog() / sanitizeLogMessage().
 *
 * SCOPE IS INTENTIONALLY PARTIAL. The worker still has ~173 un-redacted error
 * logs across ~38 files; those are tracked for PR2c-2b and are NOT guarded yet.
 * Only files already cleaned by the redaction PRs below are protected, so this
 * guard prevents *regressions* in cleaned areas without blocking the rest.
 *
 * To extend coverage later, add files to PROTECTED_FILES as they are cleaned.
 */
import { readFileSync } from 'node:fs';

// Files already redacted — guarded against regressions.
const PROTECTED_FILES = [
  // representative routes (initial redaction PR)
  'apps/worker/src/routes/webhook.ts',
  'apps/worker/src/routes/forms.ts',
  'apps/worker/src/routes/liff.ts',
  'apps/worker/src/routes/booking.ts',
  // PR2c-1 (high-risk logs)
  'apps/worker/src/client/form.ts',
  'apps/worker/src/routes/broadcasts.ts',
  // PR2c-2a (external API error logs); broadcasts.ts shared with PR2c-1 — listed once above
  'apps/worker/src/routes/stripe.ts',
  'apps/worker/src/routes/calendar.ts',
  'apps/worker/src/routes/webhooks.ts',
  'apps/worker/src/routes/line-accounts.ts',
  'apps/worker/src/index.ts',
  'apps/worker/src/client/booking.ts',
];

// Bare identifiers that denote an unredacted error/exception object.
const BARE_ERROR_ARG = /^(err|error|e|ex|reason)$/;
const SAFE_WRAPPER = /\b(redactForLog|sanitizeLogMessage)\s*\(/;
const CONSOLE_CALL = /console\s*\.\s*(?:log|warn|error|info|debug)\s*\(/g;

/** Replace comment bytes with spaces so commented-out code never triggers the guard.
 *  String/template literals are preserved (their content can't false-positive: a
 *  string arg keeps its quotes, so it never equals a bare identifier). */
function stripComments(src) {
  let out = '';
  let i = 0;
  let str = null; // current string delimiter or null
  let prev = '';
  while (i < src.length) {
    const ch = src[i];
    const next = src[i + 1];
    if (str) {
      out += ch;
      if (ch === str && prev !== '\\') str = null;
      prev = ch;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      str = ch;
      out += ch;
      prev = ch;
      i++;
      continue;
    }
    if (ch === '/' && next === '/') {
      while (i < src.length && src[i] !== '\n') {
        out += ' ';
        i++;
      }
      prev = '';
      continue;
    }
    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        out += src[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i += 2;
      prev = '';
      continue;
    }
    out += ch;
    prev = ch;
    i++;
  }
  return out;
}

/** Return the balanced argument text for a call whose '(' is at openIdx. */
function readBalancedArgs(src, openIdx) {
  let depth = 0;
  let str = null;
  let prev = '';
  for (let i = openIdx; i < src.length; i++) {
    const ch = src[i];
    if (str) {
      if (ch === str && prev !== '\\') str = null;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      str = ch;
    } else if (ch === '(') {
      depth++;
    } else if (ch === ')') {
      depth--;
      if (depth === 0) return src.slice(openIdx + 1, i);
    }
    prev = ch;
  }
  return src.slice(openIdx + 1); // unbalanced (shouldn't happen in valid TS)
}

/** Split an argument string on top-level commas (ignoring nested (){}[] and strings). */
function splitTopLevelArgs(s) {
  const args = [];
  let depth = 0;
  let str = null;
  let prev = '';
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (str) {
      cur += ch;
      if (ch === str && prev !== '\\') str = null;
    } else if (ch === '"' || ch === "'" || ch === '`') {
      str = ch;
      cur += ch;
    } else if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      cur += ch;
    } else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      cur += ch;
    } else if (ch === ',' && depth === 0) {
      args.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
    prev = ch;
  }
  if (cur.trim() !== '') args.push(cur);
  return args.map((a) => a.trim());
}

const violations = [];
let scanned = 0;

for (const file of PROTECTED_FILES) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    console.error(`redacted-log guard: cannot read protected file: ${file}`);
    process.exitCode = 1;
    continue;
  }
  scanned++;
  const src = stripComments(raw);
  CONSOLE_CALL.lastIndex = 0;
  let m;
  while ((m = CONSOLE_CALL.exec(src)) !== null) {
    const openIdx = src.indexOf('(', m.index + 'console'.length);
    if (openIdx === -1) continue;
    const argsText = readBalancedArgs(src, openIdx);
    if (SAFE_WRAPPER.test(argsText)) continue; // wrapped — OK
    const args = splitTopLevelArgs(argsText);
    if (args.some((a) => BARE_ERROR_ARG.test(a))) {
      const line = src.slice(0, m.index).split('\n').length;
      const bare = args.find((a) => BARE_ERROR_ARG.test(a));
      violations.push(`${file}:${line}  passes bare "${bare}" to console.* — wrap with redactForLog()`);
    }
  }
}

if (violations.length > 0) {
  console.error('\n❌ redacted-log guard failed: raw error objects in protected files.\n');
  for (const v of violations) console.error('  ' + v);
  console.error(
    `\n${violations.length} violation(s) across ${PROTECTED_FILES.length} protected files.\n` +
      'Wrap the error with redactForLog(err) (or sanitizeLogMessage(text) for strings).\n',
  );
  process.exit(1);
}

console.log(`✅ redacted-log guard: ${scanned}/${PROTECTED_FILES.length} protected files clean (no bare error logging).`);

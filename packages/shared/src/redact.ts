const REDACTED = '<redacted>';

const SECRET_NAME_PATTERN =
  /\b(?:LINE_CHANNEL_SECRET|LINE_CHANNEL_ACCESS_TOKEN|CF_API_TOKEN|ADMIN_API_KEY)\b(?:\s*[:=]\s*[^\s&,;}\]]+)?/g;
const AUTHORIZATION_PATTERN = /\bAuthorization\s*[:=]\s*[^\r\n]+/gi;
const BEARER_PATTERN = /\bBearer\s+[^\s,;}\]]+/gi;
// key=value or key: value (unquoted), preserving the original separator.
const SECRET_PARAMETER_PATTERN =
  /\b(channel_secret|access_token|client_secret|stripe_signature)(\s*[:=]\s*)[^\s&,;}\]]+/gi;
// JSON-style "key": "value" (e.g. OAuth/LIFF error bodies), preserving the key/colon.
const SECRET_JSON_PATTERN =
  /("(?:channel_secret|access_token|client_secret|authorization)"\s*:\s*)"[^"]*"/gi;
const STRIPE_SECRET_PATTERN = /\b(?:whsec|sk_live|sk_test|rk_live|rk_test)_[A-Za-z0-9_-]+/g;

/** Remove credentials that may be embedded in error messages or response text. */
export function sanitizeLogMessage(message: string): string {
  return message
    .replace(SECRET_NAME_PATTERN, REDACTED)
    .replace(AUTHORIZATION_PATTERN, `Authorization: ${REDACTED}`)
    .replace(SECRET_JSON_PATTERN, (_match, prefix: string) => `${prefix}"${REDACTED}"`)
    .replace(BEARER_PATTERN, `Bearer ${REDACTED}`)
    .replace(SECRET_PARAMETER_PATTERN, (_match, key: string, sep: string) => `${key}${sep}${REDACTED}`)
    .replace(STRIPE_SECRET_PATTERN, REDACTED);
}

type RedactedError = {
  name: string;
  message: string;
  status?: number | string;
};

/** Keep logs useful without serializing arbitrary error fields, stacks, or causes. */
export function redactForLog(error: unknown): RedactedError {
  if (error && typeof error === 'object') {
    const value = error as Record<string, unknown>;
    const name = typeof value.name === 'string' ? value.name : 'Error';
    const message = typeof value.message === 'string' ? value.message : 'Unknown error';
    const result: RedactedError = {
      name: sanitizeLogMessage(name),
      message: sanitizeLogMessage(message),
    };

    if (typeof value.status === 'number') {
      result.status = value.status;
    } else if (typeof value.status === 'string') {
      result.status = sanitizeLogMessage(value.status);
    }

    return result;
  }

  return {
    name: 'Error',
    message: sanitizeLogMessage(typeof error === 'string' ? error : String(error)),
  };
}

function maskPrefix(value: string | null | undefined, visible: number, fallback: string): string {
  if (!value || value.length <= visible) return fallback;
  return `${value.slice(0, visible)}…`;
}

export function maskLineUserId(value: string | null | undefined): string {
  return maskPrefix(value, 5, '<redacted_line_user_id>');
}

export function maskFriendId(value: string | null | undefined): string {
  return maskPrefix(value, 5, '<redacted_friend_id>');
}

export function maskXUsername(value: string | null | undefined): string {
  return maskPrefix(value, 2, '<redacted_x_username>');
}

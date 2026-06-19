import { describe, expect, test } from 'vitest';
import {
  maskFriendId,
  maskLineUserId,
  maskXUsername,
  redactForLog,
  sanitizeLogMessage,
} from './redact';

describe('sanitizeLogMessage', () => {
  test.each([
    'Bearer bearer-token-value',
    'Authorization: Basic raw-credentials',
    'channel_secret=channel-secret-value',
    'access_token=access-token-value',
    'client_secret=client-secret-value',
    'stripe_signature=stripe-signature-value',
    'whsec_webhook-secret',
    'sk_live_live-secret',
    'sk_test_test-secret',
    'LINE_CHANNEL_SECRET=line-secret',
    'LINE_CHANNEL_ACCESS_TOKEN=line-access-token',
    'CF_API_TOKEN=cloudflare-token',
    'ADMIN_API_KEY=admin-key',
  ])('redacts secret-bearing text: %s', (input) => {
    const output = sanitizeLogMessage(`Request failed: ${input}`);

    expect(output).toContain('<redacted>');
    expect(output).not.toContain(input.split(/[ :=]/).at(-1));
  });
});

describe('redactForLog', () => {
  test('returns only safe error fields and sanitizes message credentials', () => {
    const error = Object.assign(
      new Error('upstream rejected Bearer super-secret-token and access_token=query-secret'),
      {
        status: 401,
        response: { headers: { Authorization: 'Bearer another-secret' } },
        cause: new Error('LINE_CHANNEL_SECRET=deep-secret'),
      },
    );

    expect(redactForLog(error)).toEqual({
      name: 'Error',
      message: 'upstream rejected Bearer <redacted> and access_token=<redacted>',
      status: 401,
    });
  });

  test('sanitizes string errors', () => {
    expect(redactForLog('stripe failed: whsec_do-not-log')).toEqual({
      name: 'Error',
      message: 'stripe failed: <redacted>',
    });
  });
});

describe('identifier masking', () => {
  test('uses the required prefixes without exposing short identifiers', () => {
    expect(maskLineUserId('U123456789')).toBe('U1234…');
    expect(maskFriendId('friend-uuid-value')).toBe('frien…');
    expect(maskXUsername('username')).toBe('us…');
    expect(maskLineUserId('U123')).toBe('<redacted_line_user_id>');
    expect(maskXUsername('x')).toBe('<redacted_x_username>');
  });

  test('maskFriendId short value returns the fallback, never the raw value', () => {
    expect(maskFriendId('abc')).toBe('<redacted_friend_id>');
    expect(maskFriendId('abcde')).toBe('<redacted_friend_id>'); // length <= visible(5)
    expect(maskFriendId('abcde')).not.toContain('abcde');
  });
});

describe('sanitizeLogMessage — JSON-style and restricted-key secrets', () => {
  test.each([
    ['access_token', '{"access_token":"super-secret-token"}', 'super-secret-token'],
    ['client_secret', '{"client_secret":"client-secret-value"}', 'client-secret-value'],
    ['channel_secret', '{"channel_secret":"channel-secret-value"}', 'channel-secret-value'],
    ['authorization', '{"authorization":"Bearer json-bearer-token"}', 'json-bearer-token'],
  ])('redacts JSON "%s" value', (_key, input, secret) => {
    const output = sanitizeLogMessage(`Upstream error body: ${input}`);
    expect(output).toContain('<redacted>');
    expect(output).not.toContain(secret);
  });

  test.each([
    'rk_live_restricted-live-secret',
    'rk_test_restricted-test-secret',
  ])('redacts Stripe restricted key: %s', (input) => {
    const output = sanitizeLogMessage(`Stripe call failed: ${input}`);
    expect(output).toContain('<redacted>');
    expect(output).not.toContain(input);
  });
});

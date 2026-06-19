import { describe, expect, test, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

const lineClientMocks = vi.hoisted(() => ({
  getProfile: vi.fn(),
  replyMessage: vi.fn(),
  pushMessage: vi.fn(),
}));

// Stub the DB graph — these tests focus on webhook guard behavior and the
// first-contact friend registration path without touching real D1/LINE.
vi.mock('@line-crm/db', () => ({
  upsertFriend: vi.fn(),
  updateFriendFollowStatus: vi.fn(),
  getFriendByLineUserId: vi.fn(),
  getScenarios: vi.fn(),
  enrollFriendInScenario: vi.fn(),
  getScenarioSteps: vi.fn(),
  advanceFriendScenario: vi.fn(),
  completeFriendScenario: vi.fn(),
  upsertChatOnMessage: vi.fn(),
  getLineAccounts: vi.fn().mockResolvedValue([]),
  jstNow: vi.fn(),
  computeNextDeliveryAt: vi.fn(),
  resolveStepContent: vi.fn(),
  addTagToFriend: vi.fn(),
  getEntryRouteByRefCode: vi.fn(),
  getMessageTemplateById: vi.fn(),
}));

vi.mock('@line-crm/line-sdk', async () => {
  const actual = await vi.importActual<typeof import('@line-crm/line-sdk')>('@line-crm/line-sdk');
  return {
    ...actual,
    verifySignature: vi.fn(),
    LineClient: vi.fn().mockImplementation(() => lineClientMocks),
  };
});

vi.mock('../services/event-bus.js', () => ({
  fireEvent: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../services/step-delivery.js', () => ({
  buildMessage: vi.fn(),
  expandVariables: vi.fn(),
}));

import { verifySignature, LineClient } from '@line-crm/line-sdk';
import {
  addTagToFriend,
  advanceFriendScenario,
  completeFriendScenario,
  computeNextDeliveryAt,
  enrollFriendInScenario,
  getEntryRouteByRefCode,
  getFriendByLineUserId,
  getLineAccounts,
  getMessageTemplateById,
  getScenarioSteps,
  getScenarios,
  jstNow,
  resolveStepContent,
  updateFriendFollowStatus,
  upsertChatOnMessage,
  upsertFriend,
} from '@line-crm/db';
import { fireEvent } from '../services/event-bus.js';
import { webhook } from './webhook.js';

function setupApp() {
  const app = new Hono();
  app.route('/', webhook);
  return app;
}

const baseEnv = {
  DB: {} as D1Database,
  LINE_CHANNEL_SECRET: 'env-default-secret',
  LINE_CHANNEL_ACCESS_TOKEN: 'env-default-token',
} as Record<string, unknown>;

const baseExecutionCtx = {
  waitUntil: vi.fn(),
  passThroughOnException: vi.fn(),
  props: {},
} as unknown as ExecutionContext;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getLineAccounts).mockResolvedValue([]);
});

describe('POST /webhook — DoS defenses (#104)', () => {
  test('rejects with 413 when Content-Length declares an oversized body', async () => {
    const app = setupApp();
    const res = await app.request(
      '/webhook',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(2 * 1024 * 1024), // 2 MiB > 1 MiB cap
          'X-Line-Signature': 'whatever',
        },
        body: JSON.stringify({ events: [] }),
      },
      baseEnv,
      baseExecutionCtx,
    );
    expect(res.status).toBe(413);
    // Signature verification must not even be attempted on an oversized body.
    expect(verifySignature).not.toHaveBeenCalled();
  });

  test('rejects with 413 when actual body exceeds the cap even if Content-Length is absent', async () => {
    const app = setupApp();
    const oversizedBody = 'x'.repeat(1024 * 1024 + 1);
    const res = await app.request(
      '/webhook',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Line-Signature': 'whatever',
        },
        body: oversizedBody,
      },
      baseEnv,
      baseExecutionCtx,
    );
    expect(res.status).toBe(413);
    expect(verifySignature).not.toHaveBeenCalled();
  });

  test('verifies signature before parsing JSON — malformed body with invalid signature never reaches the parser', async () => {
    vi.mocked(verifySignature).mockResolvedValue(false);

    const app = setupApp();
    // 44-char signature (valid HMAC-SHA256 base64 length) so it clears the
    // length pre-check and reaches verifySignature. Malformed JSON body: if
    // signature were verified *after* parse (old behavior), we'd hit the
    // parser-failure branch first. With signature-first, we get the invalid-
    // signature branch and never attempt to parse.
    const validShapedSignature = 'A'.repeat(43) + '=';
    const res = await app.request(
      '/webhook',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Line-Signature': validShapedSignature,
        },
        body: '{not valid json',
      },
      baseEnv,
      baseExecutionCtx,
    );
    expect(res.status).toBe(200);
    // verifySignature must run; rejection happens before any parse attempt.
    expect(verifySignature).toHaveBeenCalled();
    expect(verifySignature).toHaveBeenCalledWith('env-default-secret', '{not valid json', validShapedSignature);
  });

  test('rejects unsigned or malformed-signature requests without hitting verifySignature or D1', async () => {
    const app = setupApp();
    const res = await app.request(
      '/webhook',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Missing X-Line-Signature header entirely.
        },
        body: JSON.stringify({ events: [] }),
      },
      baseEnv,
      baseExecutionCtx,
    );
    expect(res.status).toBe(200);
    // Fast-rejected before any crypto / DB work.
    expect(verifySignature).not.toHaveBeenCalled();
  });
});

describe('POST /webhook — first-contact existing friends', () => {
  test('auto-registers an unknown text-message sender without firing friend_add handling', async () => {
    vi.mocked(verifySignature).mockResolvedValue(true);
    vi.mocked(getFriendByLineUserId).mockResolvedValue(null);
    vi.mocked(jstNow).mockReturnValue('2026-06-18T12:00:00.000+09:00');
    lineClientMocks.getProfile.mockResolvedValue({
      userId: 'U-existing',
      displayName: 'Existing Friend',
      pictureUrl: 'https://example.com/profile.jpg',
      statusMessage: 'hello',
    });
    vi.mocked(upsertFriend).mockResolvedValue({
      id: 'friend-1',
      line_user_id: 'U-existing',
      display_name: 'Existing Friend',
      picture_url: 'https://example.com/profile.jpg',
      status_message: 'hello',
      is_following: 1,
      user_id: null,
      line_account_id: null,
      metadata: '{}',
      first_tracked_link_id: null,
      created_at: '2026-06-18T12:00:00.000+09:00',
      updated_at: '2026-06-18T12:00:00.000+09:00',
    });
    vi.mocked(upsertChatOnMessage).mockResolvedValue({
      id: 'chat-1',
      friend_id: 'friend-1',
      operator_id: null,
      status: 'unread',
      notes: null,
      last_message_at: '2026-06-18T12:00:00.000+09:00',
      created_at: '2026-06-18T12:00:00.000+09:00',
      updated_at: '2026-06-18T12:00:00.000+09:00',
    });

    const stmt = {
      bind: vi.fn(),
      run: vi.fn().mockResolvedValue({}),
      all: vi.fn().mockResolvedValue({ results: [] }),
    };
    stmt.bind.mockReturnValue(stmt);
    const db = { prepare: vi.fn().mockReturnValue(stmt) } as unknown as D1Database;

    const executionCtx = {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn(),
      props: {},
    } as unknown as ExecutionContext;

    const app = setupApp();
    const validShapedSignature = 'A'.repeat(43) + '=';
    const res = await app.request(
      '/webhook',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Line-Signature': validShapedSignature,
        },
        body: JSON.stringify({
          destination: 'bot',
          events: [
            {
              type: 'message',
              replyToken: 'reply-token',
              message: { type: 'text', id: 'message-1', text: 'こんにちは' },
              timestamp: Date.now(),
              source: { type: 'user', userId: 'U-existing' },
              webhookEventId: 'event-1',
              deliveryContext: { isRedelivery: false },
              mode: 'active',
            },
          ],
        }),
      },
      { ...baseEnv, DB: db },
      executionCtx,
    );

    expect(res.status).toBe(200);
    const processing = vi.mocked(executionCtx.waitUntil).mock.calls[0]?.[0] as Promise<unknown>;
    await processing;

    expect(lineClientMocks.getProfile).toHaveBeenCalledWith('U-existing');
    expect(upsertFriend).toHaveBeenCalledWith(db, {
      lineUserId: 'U-existing',
      displayName: 'Existing Friend',
      pictureUrl: 'https://example.com/profile.jpg',
      statusMessage: 'hello',
    });
    expect(upsertChatOnMessage).toHaveBeenCalledWith(db, 'friend-1');
    expect(fireEvent).toHaveBeenCalledWith(
      db,
      'message_received',
      expect.objectContaining({ friendId: 'friend-1' }),
      'env-default-token',
      null,
    );
    expect(getScenarios).not.toHaveBeenCalled();
    expect(enrollFriendInScenario).not.toHaveBeenCalled();

    // Keep the unrelated DB stubs quiet but type-checked as mocked imports.
    expect(updateFriendFollowStatus).not.toHaveBeenCalled();
    expect(getScenarioSteps).not.toHaveBeenCalled();
    expect(advanceFriendScenario).not.toHaveBeenCalled();
    expect(completeFriendScenario).not.toHaveBeenCalled();
    expect(computeNextDeliveryAt).not.toHaveBeenCalled();
    expect(resolveStepContent).not.toHaveBeenCalled();
    expect(addTagToFriend).not.toHaveBeenCalled();
    expect(getEntryRouteByRefCode).not.toHaveBeenCalled();
    expect(getMessageTemplateById).not.toHaveBeenCalled();
  });
});

describe('POST /webhook — signature gating & multi-account resolution', () => {
  const VALID_SHAPED_SIG = 'A'.repeat(43) + '='; // 44-char base64 (HMAC-SHA256 length)

  function freshCtx(): ExecutionContext {
    return {
      waitUntil: vi.fn(),
      passThroughOnException: vi.fn(),
      props: {},
    } as unknown as ExecutionContext;
  }

  function post(body: string, ctx: ExecutionContext, headers: Record<string, string> = {}) {
    return setupApp().request(
      '/webhook',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body,
      },
      baseEnv,
      ctx,
    );
  }

  // (#1, #5) Valid env-secret signature clears verification and enters async processing.
  test('valid env-secret signature enters async processing', async () => {
    vi.mocked(verifySignature).mockResolvedValue(true);
    const ctx = freshCtx();
    const body = JSON.stringify({ destination: 'bot', events: [] });

    const res = await post(body, ctx, { 'X-Line-Signature': VALID_SHAPED_SIG });

    expect(res.status).toBe(200);
    expect(verifySignature).toHaveBeenCalledWith('env-default-secret', body, VALID_SHAPED_SIG);
    // waitUntil is only reached AFTER the signature gate — proves processing started.
    expect(ctx.waitUntil).toHaveBeenCalled();
  });

  // (#2, #4) 44-char but invalid signature with well-formed JSON: HTTP 200, but no downstream work.
  test('invalid signature with well-formed JSON returns 200 without starting processing', async () => {
    vi.mocked(verifySignature).mockResolvedValue(false); // env + (empty) D1 both fail
    const ctx = freshCtx();
    const body = JSON.stringify({
      destination: 'bot',
      events: [
        {
          type: 'follow',
          replyToken: 'reply-token',
          timestamp: 1,
          source: { type: 'user', userId: 'U-attacker' },
          mode: 'active',
        },
      ],
    });

    const res = await post(body, ctx, { 'X-Line-Signature': VALID_SHAPED_SIG });

    expect(res.status).toBe(200); // by design: 200 to avoid LINE retries / info leak
    expect(verifySignature).toHaveBeenCalled();
    // The gate held: no async processing, no event handling, even with a valid-looking event.
    expect(ctx.waitUntil).not.toHaveBeenCalled();
    expect(fireEvent).not.toHaveBeenCalled();
    expect(upsertFriend).not.toHaveBeenCalled();
  });

  // (#3) Missing signature header is fast-rejected before any crypto or D1 access.
  test('missing signature header skips verifySignature and the D1 account lookup', async () => {
    const ctx = freshCtx();
    const body = JSON.stringify({ destination: 'bot', events: [] });

    const res = await post(body, ctx); // no X-Line-Signature

    expect(res.status).toBe(200);
    expect(verifySignature).not.toHaveBeenCalled();
    expect(getLineAccounts).not.toHaveBeenCalled();
    expect(ctx.waitUntil).not.toHaveBeenCalled();
  });

  // (#8) Even malformed JSON is signature-verified first; parse failure returns 200 safely.
  test('valid signature + malformed JSON verifies first, then returns 200 without processing', async () => {
    vi.mocked(verifySignature).mockResolvedValue(true);
    const ctx = freshCtx();
    const body = '{not valid json';

    const res = await post(body, ctx, { 'X-Line-Signature': VALID_SHAPED_SIG });

    expect(res.status).toBe(200);
    expect(verifySignature).toHaveBeenCalledWith('env-default-secret', body, VALID_SHAPED_SIG);
    // Parse failure is caught before processing — no async work started, no crash.
    expect(ctx.waitUntil).not.toHaveBeenCalled();
  });

  // (#6) env secret fails → an ACTIVE line_accounts secret matches → that account's token is used.
  test('falls back to an active line_accounts secret when env secret does not match', async () => {
    vi.mocked(verifySignature).mockImplementation(
      async (secret: string) => secret === 'db-account-secret',
    );
    vi.mocked(getLineAccounts).mockResolvedValue([
      {
        id: 'acc-db',
        is_active: 1,
        channel_secret: 'db-account-secret',
        channel_access_token: 'db-account-token',
      },
    ] as never);
    const ctx = freshCtx();
    const body = JSON.stringify({ destination: 'bot', events: [] });

    const res = await post(body, ctx, { 'X-Line-Signature': VALID_SHAPED_SIG });

    expect(res.status).toBe(200);
    expect(verifySignature).toHaveBeenCalledWith('env-default-secret', body, VALID_SHAPED_SIG);
    expect(verifySignature).toHaveBeenCalledWith('db-account-secret', body, VALID_SHAPED_SIG);
    // downstream LINE client is built with the MATCHED account's access token, not the env one.
    expect(LineClient).toHaveBeenCalledWith('db-account-token');
    expect(ctx.waitUntil).toHaveBeenCalled();
  });

  // (#7) Inactive line_accounts must never be used as a verification candidate.
  test('inactive line_accounts are skipped during signature verification', async () => {
    vi.mocked(verifySignature).mockImplementation(
      async (secret: string) => secret === 'inactive-secret',
    );
    vi.mocked(getLineAccounts).mockResolvedValue([
      {
        id: 'acc-inactive',
        is_active: 0,
        channel_secret: 'inactive-secret',
        channel_access_token: 'inactive-token',
      },
    ] as never);
    const ctx = freshCtx();
    const body = JSON.stringify({ destination: 'bot', events: [] });

    const res = await post(body, ctx, { 'X-Line-Signature': VALID_SHAPED_SIG });

    expect(res.status).toBe(200);
    // The inactive account's secret must never be handed to verifySignature.
    expect(verifySignature).not.toHaveBeenCalledWith(
      'inactive-secret',
      expect.anything(),
      expect.anything(),
    );
    // Verification ultimately failed → no processing, no LINE client.
    expect(ctx.waitUntil).not.toHaveBeenCalled();
    expect(LineClient).not.toHaveBeenCalled();
  });
});

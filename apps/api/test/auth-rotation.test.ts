import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// 用 hoisted 持有可替换的内存 Prisma，模拟真实的单例模块导出。
const state = vi.hoisted(() => ({ fake: null as unknown as Record<string, unknown> }));

vi.mock("../src/lib/prisma.js", () => ({
  get prisma() {
    return state.fake;
  },
}));

// 沙箱内 argon2 原生绑定未构建（import 会段错误），轮换逻辑不依赖它，用桩替代。
vi.mock("argon2", () => ({
  default: {
    argon2id: 0,
    hash: vi.fn(async () => "$argon2id$mock"),
    verify: vi.fn(async () => true),
  },
}));

import { rotateRefreshSession } from "../src/services/auth-service.js";
import { createRefreshToken } from "../src/lib/security.js";

interface StoredSession {
  id: string;
  userId: string;
  familyId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedBy: string | null;
}

interface StoredAudit {
  userId: string | null;
  action: string;
  resource: string;
  resourceId: string | null;
  result: string;
  traceId: string | undefined;
}

interface TxClient {
  refreshSession: {
    create(args: { data: Partial<StoredSession> }): Promise<StoredSession>;
    update(args: { where: { id: string }; data: Partial<StoredSession> }): Promise<StoredSession>;
    updateMany(args: {
      where: { id?: string; familyId?: string; tokenHash?: string; revokedAt?: Date | null };
      data: Partial<StoredSession>;
    }): Promise<{ count: number }>;
  };
}

function buildPrisma() {
  const sessions: StoredSession[] = [];
  const auditLogs: StoredAudit[] = [];
  // 事务互斥：模拟 PostgreSQL 行级锁，保证两个并发事务的事务体不会交错执行。
  let txChain: Promise<unknown> = Promise.resolve();

  function matchWhere(row: StoredSession, where: Record<string, unknown>): boolean {
    for (const [key, expected] of Object.entries(where)) {
      if (key === "revokedAt" && expected === null) {
        if (row.revokedAt !== null) return false;
        continue;
      }
      if ((row as Record<string, unknown>)[key] !== expected) return false;
    }
    return true;
  }

  function makeTxClient(state: StoredSession[], commit: (next: StoredSession[]) => void): TxClient {
    return {
      refreshSession: {
        async create({ data }) {
          const row: StoredSession = {
            id: crypto.randomUUID(),
            userId: data.userId!,
            familyId: data.familyId!,
            tokenHash: data.tokenHash!,
            expiresAt: data.expiresAt!,
            revokedAt: data.revokedAt ?? null,
            replacedBy: data.replacedBy ?? null,
          };
          state.push(row);
          return structuredClone(row);
        },
        async update({ where, data }) {
          const index = state.findIndex((row) => row.id === where.id);
          if (index < 0) throw Object.assign(new Error("not found"), { code: "P2025" });
          state[index] = { ...state[index], ...data };
          return structuredClone(state[index]);
        },
        async updateMany({ where, data }) {
          let count = 0;
          for (const row of state) {
            if (matchWhere(row, where as Record<string, unknown>)) {
              Object.assign(row, data);
              count += 1;
            }
          }
          return { count };
        },
      },
    };
  }

  return {
    sessions,
    auditLogs,
    auditLog: {
      async create({ data }: { data: StoredAudit }) {
        auditLogs.push(data);
        return data;
      },
    },
    refreshSession: {
      async findUnique({ where }: { where: { tokenHash: string } }) {
        const row = sessions.find((item) => item.tokenHash === where.tokenHash);
        if (!row) return null;
        return {
          ...structuredClone(row),
          user: { id: "user-1", email: "player@example.com", status: "ACTIVE" as const },
        };
      },
      async update({ where, data }: { where: { id: string }; data: Partial<StoredSession> }) {
        const row = sessions.find((item) => item.id === where.id);
        if (!row) throw Object.assign(new Error("not found"), { code: "P2025" });
        Object.assign(row, data);
        return structuredClone(row);
      },
      async updateMany({
        where,
        data,
      }: {
        where: { id?: string; familyId?: string; tokenHash?: string; revokedAt?: Date | null };
        data: Partial<StoredSession>;
      }) {
        return makeTxClient(sessions, () => undefined).refreshSession.updateMany({ where, data });
      },
    },
    async $transaction<T>(fn: (tx: TxClient) => Promise<T>): Promise<T> {
      // 串行化执行：后到的事务会在持锁期间看到前一个事务已提交的状态（READ COMMITTED 语义）。
      const run = txChain.then(async () => {
        const snapshot = structuredClone(sessions);
        try {
          const result = await fn(makeTxClient(snapshot, () => undefined));
          sessions.splice(0, sessions.length, ...snapshot);
          return result;
        } catch (error) {
          throw error; // 回滚：丢弃快照，不影响已提交的 sessions
        }
      });
      txChain = run.catch(() => undefined);
      return run;
    },
  };
}

function makeReply() {
  const calls: Array<{ op: "set" | "clear"; value?: string }> = [];
  return {
    calls,
    setCookie(_name: string, value: string) {
      calls.push({ op: "set", value });
    },
    clearCookie(_name: string, _opts?: unknown) {
      calls.push({ op: "clear" });
    },
  };
}

function makeRequest() {
  return { ip: "127.0.0.1", headers: { "user-agent": "vitest" }, id: "trace-1" };
}

function seedSession(): { raw: string; session: StoredSession } {
  const token = createRefreshToken();
  const session: StoredSession = {
    id: crypto.randomUUID(),
    userId: "user-1",
    familyId: token.familyId,
    tokenHash: token.hash,
    expiresAt: new Date(Date.now() + 30 * 24 * 3600_000),
    revokedAt: null,
    replacedBy: null,
  };
  (db()).sessions.push(session);
  return { raw: token.raw, session };
}

beforeEach(() => {
  state.fake = buildPrisma();
});

function db() {
  return state.fake as unknown as { sessions: StoredSession[]; auditLogs: StoredAudit[] };
}

beforeAll(() => {
  // security/env 等模块首次读取配置时需要的最小环境变量
  process.env.NODE_ENV ??= "test";
  process.env.DATABASE_URL ??= "postgresql://user:pass@localhost:5432/practice_test";
  process.env.REDIS_URL ??= "redis://localhost:6379";
  process.env.JWT_ACCESS_SECRET ??= "test-jwt-access-secret-at-least-32-chars";
  process.env.REFRESH_TOKEN_PEPPER ??= "test-refresh-pepper-at-least-32-chars";
  process.env.S3_ENDPOINT ??= "http://localhost:9000";
  process.env.S3_ACCESS_KEY ??= "test";
  process.env.S3_SECRET_KEY ??= "test";
  process.env.PUBLIC_API_ORIGIN ??= "http://localhost:3000";
  process.env.WEB_ORIGIN ??= "http://localhost:5173";
});

describe("rotateRefreshSession 并发轮换安全", () => {
  it("正常轮换：旧令牌被撤销且只产生一个后继会话", async () => {
    const { raw, session } = seedSession();
    const reply = makeReply();

    const result = await rotateRefreshSession(
      reply as never,
      makeRequest() as never,
      raw,
    );

    expect(result.accessToken).toBeTruthy();
    const stored = db().sessions;
    const old = stored.find((row) => row.id === session.id)!;
    expect(old.revokedAt).toBeInstanceOf(Date);
    expect(old.replacedBy).toBeTruthy();
    const successors = stored.filter((row) => row.familyId === session.familyId && row.id !== session.id);
    expect(successors).toHaveLength(1);
    expect(old.replacedBy).toBe(successors[0]!.id);
    expect(successors[0]!.revokedAt).toBeNull();
    expect(reply.calls).toEqual([{ op: "set", value: expect.stringMatching(/.+/) }]);
  });

  it("并发轮换同一旧令牌：只有一个请求成功，失败方回滚且不产生第二个后继会话", async () => {
    const { raw, session } = seedSession();
    const replyA = makeReply();
    const replyB = makeReply();

    const [outcomeA, outcomeB] = await Promise.allSettled([
      rotateRefreshSession(replyA as never, makeRequest() as never, raw),
      rotateRefreshSession(replyB as never, makeRequest() as never, raw),
    ]);

    const outcomes = [outcomeA, outcomeB];
    const fulfilled = outcomes.filter((o): o is PromiseFulfilledResult<unknown> => o.status === "fulfilled");
    const rejected = outcomes.filter((o): o is PromiseRejectedResult => o.status === "rejected");
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);

    const familyRows = db().sessions.filter(
      (row) => row.familyId === session.familyId,
    );
    // 旧令牌 + 唯一一个后继会话，绝无第二个后继
    expect(familyRows).toHaveLength(2);
    const old = familyRows.find((row) => row.id === session.id)!;
    expect(old.revokedAt).toBeInstanceOf(Date);
    const successor = familyRows.find((row) => row.id !== session.id)!;
    expect(old.replacedBy).toBe(successor.id);

    // 复用触发：会话族被整体撤销（连胜出方刚签发的后继也被撤销）
    expect(successor.revokedAt).toBeInstanceOf(Date);

    // 胜出方设置了新 Cookie，失败方只清除 Cookie，绝不下发第二个后继令牌
    const winnerReply = outcomeA.status === "fulfilled" ? replyA : replyB;
    const loserReply = outcomeA.status === "fulfilled" ? replyB : replyA;
    expect(winnerReply.calls.filter((c) => c.op === "set")).toHaveLength(1);
    expect(loserReply.calls).toContainEqual({ op: "clear" });
    expect(loserReply.calls.find((c) => c.op === "set")).toBeUndefined();

    const rejection = rejected[0]!.reason as { statusCode?: number; code?: string };
    expect(rejection.statusCode).toBe(401);
  });

  it("旧令牌在首次轮换后被再次使用（顺序复用）：撤销整个会话族", async () => {
    const { raw, session } = seedSession();

    await rotateRefreshSession(makeReply() as never, makeRequest() as never, raw);
    await expect(
      rotateRefreshSession(makeReply() as never, makeRequest() as never, raw),
    ).rejects.toMatchObject({ statusCode: 401 });

    const familyRows = db().sessions.filter(
      (row) => row.familyId === session.familyId,
    );
    expect(familyRows.every((row) => row.revokedAt instanceof Date)).toBe(true);

    const audits = db().auditLogs;
    expect(audits.some((entry) => entry.action === "AUTH_REFRESH_REUSE")).toBe(true);
  });

  it("并发复用失败方也会留下安全审计记录", async () => {
    const { raw } = seedSession();
    await Promise.allSettled([
      rotateRefreshSession(makeReply() as never, makeRequest() as never, raw),
      rotateRefreshSession(makeReply() as never, makeRequest() as never, raw),
    ]);
    const audits = db().auditLogs;
    expect(audits.filter((entry) => entry.action === "AUTH_REFRESH_REUSE")).toHaveLength(1);
  });

  it("未知令牌直接拒绝，不产生任何会话", async () => {
    const reply = makeReply();
    const forged = createRefreshToken().raw;
    await expect(
      rotateRefreshSession(reply as never, makeRequest() as never, forged),
    ).rejects.toMatchObject({ statusCode: 401 });
    expect(db().sessions).toHaveLength(0);
    expect(reply.calls).toContainEqual({ op: "clear" });
  });
});

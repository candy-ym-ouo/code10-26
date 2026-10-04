import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { FastifyReply, FastifyRequest } from "fastify";

interface SessionRow {
  id: string;
  userId: string;
  familyId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedBy: string | null;
}

interface UserRow {
  id: string;
  email: string;
  status: "ACTIVE" | "LOCKED" | "DELETING";
}

const db = vi.hoisted(() => {
  const rows: SessionRow[] = [];
  const users: UserRow[] = [];
  const auditLogs: Array<Record<string, unknown>> = [];
  // 模拟 PostgreSQL 行锁：认领旧令牌与签发后继必须串行提交。
  let chain: Promise<unknown> = Promise.resolve();
  function exclusive<T>(fn: () => T): Promise<T> {
    const run = chain.then(() => fn());
    chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  const makeClient = () => ({
    refreshSession: {
      async findUnique({ where }: { where: { id?: string; tokenHash?: string } }): Promise<(SessionRow & { user: UserRow }) | null> {
        const row = rows.find((r) => (where.tokenHash ? r.tokenHash === where.tokenHash : r.id === where.id));
        if (!row) return null;
        // Prisma 返回的是独立快照，而不是活动行引用（READ COMMITTED 语义）。
        const snapshot = structuredClone(row);
        Object.assign(snapshot, { user: structuredClone(users.find((u) => u.id === row.userId) ?? null) });
        return snapshot as SessionRow & { user: UserRow };
      },
      async update({ where, data }: { where: { id: string }; data: Partial<SessionRow> }): Promise<SessionRow> {
        return exclusive(() => {
          const row = rows.find((r) => r.id === where.id);
          if (!row) throw new Error("not found");
          Object.assign(row, data);
          return structuredClone(row);
        });
      },
      async updateMany({
        where,
        data,
      }: {
        where: { id?: string; familyId?: string; revokedAt?: null };
        data: Partial<SessionRow>;
      }): Promise<{ count: number }> {
        const apply = () => {
          let count = 0;
          for (const row of rows) {
            if (where.id && row.id !== where.id) continue;
            if (where.familyId && row.familyId !== where.familyId) continue;
            if (where.revokedAt === null && row.revokedAt !== null) continue;
            Object.assign(row, data);
            count += 1;
          }
          return { count };
        };
        // 模拟 UPDATE 行锁：对同批行的写操作按到达顺序串行提交，
        // 因此失败方撤销全族时一定能看到获胜方已提交的后继会话。
        return exclusive(apply);
      },
      async create({ data }: { data: SessionRow }): Promise<SessionRow> {
        return exclusive(() => {
          rows.push(structuredClone(data));
          return structuredClone(data);
        });
      },
    },
    auditLog: {
      async create({ data }: { data: Record<string, unknown> }): Promise<Record<string, unknown>> {
        auditLogs.push(data);
        return data;
      },
    },
  });

  const client = makeClient();
  const prisma = {
    ...client,
    $transaction: async (fn: (tx: ReturnType<typeof makeClient>) => unknown) => fn(makeClient()),
  };

  return { prisma, rows, users, auditLogs };
});

vi.mock("../src/lib/prisma.js", () => ({ prisma: db.prisma }));

const request = { ip: "127.0.0.1", headers: { "user-agent": "vitest" }, id: "trace-1" } as unknown as FastifyRequest;

function makeReply() {
  return {
    setCookie: vi.fn(),
    clearCookie: vi.fn(),
  } as unknown as FastifyReply & { setCookie: ReturnType<typeof vi.fn>; clearCookie: ReturnType<typeof vi.fn> };
}

let rotateRefreshSession: typeof import("../src/services/auth-service.js").rotateRefreshSession;
let hashRefreshToken: typeof import("../src/lib/security.js").hashRefreshToken;

beforeAll(() => {
  process.env.NODE_ENV = "test";
  process.env.DATABASE_URL = "postgresql://test:test@localhost:5432/test";
  process.env.REDIS_URL = "redis://localhost:6379";
  process.env.JWT_ACCESS_SECRET = "x".repeat(48);
  process.env.REFRESH_TOKEN_PEPPER = "y".repeat(48);
  process.env.S3_ENDPOINT = "http://localhost:9000";
  process.env.S3_ACCESS_KEY = "test";
  process.env.S3_SECRET_KEY = "test";
  process.env.PUBLIC_API_ORIGIN = "http://localhost:3000";
  process.env.WEB_ORIGIN = "http://localhost:5173";
});

beforeEach(async () => {
  db.rows.length = 0;
  db.users.length = 0;
  db.auditLogs.length = 0;
  [{ rotateRefreshSession }, { hashRefreshToken }] = await Promise.all([
    import("../src/services/auth-service.js"),
    import("../src/lib/security.js"),
  ]);
});

afterEach(() => {
  vi.clearAllMocks();
});

function seedSession(rawToken: string, overrides: Partial<SessionRow> = {}, userOverrides: Partial<UserRow> = {}): SessionRow {
  const userId = overrides.userId ?? "user-1";
  db.users.push({ id: userId, email: "t@example.com", status: "ACTIVE", ...userOverrides });
  const row: SessionRow = {
    id: crypto.randomUUID(),
    userId,
    familyId: crypto.randomUUID(),
    tokenHash: hashRefreshToken(rawToken),
    expiresAt: new Date(Date.now() + 30 * 86_400_000),
    revokedAt: null,
    replacedBy: null,
    ...overrides,
  };
  db.rows.push(row);
  return row;
}

describe("rotateRefreshSession 并发轮换", () => {
  it("同一旧令牌并发轮换只签发一个后继，重复使用撤销整个会话族", async () => {
    const raw = "raw-token-under-race";
    const old = seedSession(raw);
    const replyA = makeReply();
    const replyB = makeReply();

    const [first, second] = await Promise.allSettled([
      rotateRefreshSession(replyA, request, raw),
      rotateRefreshSession(replyB, request, raw),
    ]);

    expect(first.status).toBe("fulfilled");
    expect(second.status).toBe("rejected");
    if (second.status === "rejected") {
      expect(second.reason).toMatchObject({ code: "AUTH_REQUIRED", message: "检测到会话复用，请重新登录" });
    }

    // 旧令牌只成功一次：只有一个后继会话
    expect(db.rows).toHaveLength(2);
    const successor = db.rows.find((r) => r.id !== old.id);
    expect(successor).toBeDefined();
    expect(successor?.tokenHash).not.toBe(old.tokenHash);
    expect(db.rows.find((r) => r.id === old.id)).toMatchObject({ replacedBy: successor!.id });

    // 会话族内所有会话（旧令牌 + 刚签发的后继）都被撤销
    for (const row of db.rows) {
      expect(row.revokedAt).not.toBeNull();
      expect(row.familyId).toBe(old.familyId);
    }

    // 只有获胜方下发了新 Cookie，失败方清除 Cookie
    expect(replyA.setCookie).toHaveBeenCalledTimes(1);
    expect(replyB.setCookie).not.toHaveBeenCalled();
    expect(replyB.clearCookie).toHaveBeenCalled();

    // 复用事件留痕
    expect(db.auditLogs).toHaveLength(1);
    expect(db.auditLogs[0]).toMatchObject({ action: "AUTH_REFRESH_REUSE", result: "FAILURE", userId: old.userId });
  });

  it("串行重放已轮换的旧令牌同样撤销后继并告警", async () => {
    const raw = "raw-token-replay";
    const old = seedSession(raw);

    const rotated = await rotateRefreshSession(makeReply(), request, raw);
    expect(rotated.userId).toBe(old.userId);

    await expect(rotateRefreshSession(makeReply(), request, raw)).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      message: "检测到会话复用，请重新登录",
    });

    for (const row of db.rows) expect(row.revokedAt).not.toBeNull();
    expect(db.auditLogs).toHaveLength(1);
    expect(db.auditLogs[0]).toMatchObject({ action: "AUTH_REFRESH_REUSE" });
  });
});

describe("rotateRefreshSession 常规分支", () => {
  it("正常轮换撤销旧令牌并链接到后继", async () => {
    const raw = "raw-token-ok";
    const old = seedSession(raw);
    const reply = makeReply();

    const result = await rotateRefreshSession(reply, request, raw);
    expect(result.accessToken).toBeTruthy();

    const updated = db.rows.find((r) => r.id === old.id);
    expect(updated?.revokedAt).not.toBeNull();
    expect(updated?.replacedBy).toBeTruthy();
    expect(reply.setCookie).toHaveBeenCalledTimes(1);
    expect(db.auditLogs).toHaveLength(0);
  });

  it("过期令牌仅撤销自身且不签发后继", async () => {
    const raw = "raw-token-expired";
    const old = seedSession(raw, { expiresAt: new Date(Date.now() - 1000) });

    await expect(rotateRefreshSession(makeReply(), request, raw)).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      message: "刷新会话已过期，请重新登录",
    });
    expect(db.rows).toHaveLength(1);
    expect(db.rows.find((r) => r.id === old.id)?.revokedAt).not.toBeNull();
  });

  it("用户被停用按过期处理，不产生后继", async () => {
    const raw = "raw-token-locked-user";
    seedSession(raw, {}, { status: "LOCKED" });

    await expect(rotateRefreshSession(makeReply(), request, raw)).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
    });
    expect(db.rows).toHaveLength(1);
    expect(db.rows[0]?.revokedAt).not.toBeNull();
  });

  it("未知令牌报无效且不产生审计噪音", async () => {
    seedSession("another-token");
    await expect(rotateRefreshSession(makeReply(), request, "bogus")).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
      message: "刷新会话无效，请重新登录",
    });
    expect(db.rows).toHaveLength(1);
    expect(db.auditLogs).toHaveLength(0);
  });

  it("登出后回放旧 cookie（replacedBy 为空）触发全族撤销但不记复用攻击告警", async () => {
    const raw = "raw-token-logout";
    const old = seedSession(raw, { revokedAt: new Date() });
    // 同族的另一个有效会话也应被撤销
    seedSession("sibling-token", { familyId: old.familyId });

    await expect(rotateRefreshSession(makeReply(), request, raw)).rejects.toMatchObject({
      code: "AUTH_REQUIRED",
    });
    for (const row of db.rows) expect(row.revokedAt).not.toBeNull();
    expect(db.auditLogs).toHaveLength(0);
  });
});

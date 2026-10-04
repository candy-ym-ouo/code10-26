import { randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";
import { getConfig } from "../config/env.js";
import { AppError } from "../lib/errors.js";
import { createRefreshToken, durationToMs, hashIp, hashRefreshToken, signAccessToken } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";

export const REFRESH_COOKIE = "practice_refresh";

function cookieOptions() {
  const config = getConfig();
  return {
    path: "/api/v1/auth",
    httpOnly: true,
    sameSite: "lax" as const,
    secure: config.NODE_ENV === "production" && config.PUBLIC_API_ORIGIN.startsWith("https://"),
    maxAge: Math.floor(durationToMs(config.REFRESH_TOKEN_TTL) / 1000),
  };
}

export async function issueRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  user: { id: string; email: string },
  familyId?: string,
): Promise<{ accessToken: string; refreshSessionId: string }> {
  const config = getConfig();
  const token = createRefreshToken();
  const session = await prisma.refreshSession.create({
    data: {
      userId: user.id,
      familyId: familyId ?? token.familyId,
      tokenHash: token.hash,
      expiresAt: new Date(Date.now() + durationToMs(config.REFRESH_TOKEN_TTL)),
      ipHash: hashIp(request.ip),
      userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null,
    },
  });
  reply.setCookie(REFRESH_COOKIE, token.raw, cookieOptions());
  return { accessToken: signAccessToken(user), refreshSessionId: session.id };
}

type RotationOutcome =
  | { outcome: "rotated"; accessToken: string; rawToken: string; userId: string }
  | { outcome: "invalid" }
  | { outcome: "reused" }
  | { outcome: "expired" };

/**
 * 刷新令牌轮换必须是单入口的原子操作：
 * 1. 整个查找/判定/签发过程放在同一事务内；
 * 2. 以「条件更新」作为认领旧令牌的唯一闸门（UPDATE ... WHERE revoked_at IS NULL）。
 *    PostgreSQL 的行锁会让并发轮换串行执行，只有第一个事务能匹配到该行；
 * 3. 条件更新匹配 0 行即说明旧令牌已被撤销（已被其他请求轮换或用户登出），
 *    这一定是令牌复用（含并发重复轮换），在同一事务内撤销整个会话族。
 */
export async function rotateRefreshSession(
  reply: FastifyReply,
  request: FastifyRequest,
  rawToken?: string,
): Promise<{ accessToken: string; userId: string }> {
  if (!rawToken) throw new AppError(401, "AUTH_REQUIRED", "请重新登录");

  const now = new Date();
  const token = createRefreshToken();
  const successorId = randomUUID();

  const result = await prisma.$transaction(async (tx) => {
    const current = await tx.refreshSession.findUnique({
      where: { tokenHash: hashRefreshToken(rawToken) },
      include: { user: { select: { id: true, email: true, status: true } } },
    });
    if (!current) return { outcome: "invalid" } satisfies RotationOutcome;

    if (current.revokedAt) {
      // 撤销状态在事务外被再次看到，直接撤销全族（与认领失败的处理一致）。
      await revokeFamily(tx, current.familyId, now);
      await auditReuseIfRotated(tx, request, current);
      return { outcome: "reused" } satisfies RotationOutcome;
    }

    if (current.expiresAt <= now || current.user.status !== "ACTIVE") {
      await tx.refreshSession.update({ where: { id: current.id }, data: { revokedAt: now } });
      return { outcome: "expired" } satisfies RotationOutcome;
    }

    // 原子认领：并发情况下只有一个事务能匹配到尚未撤销的这一行。
    const claimed = await tx.refreshSession.updateMany({
      where: { id: current.id, revokedAt: null },
      data: { revokedAt: now, replacedBy: successorId },
    });
    if (claimed.count === 0) {
      // 已被并发的另一个轮换撤销——旧令牌被使用了第二次，撤销整个会话族。
      const latest = await tx.refreshSession.findUnique({ where: { id: current.id } });
      await revokeFamily(tx, current.familyId, now);
      await auditReuseIfRotated(tx, request, latest ?? current);
      return { outcome: "reused" } satisfies RotationOutcome;
    }

    await tx.refreshSession.create({
      data: {
        id: successorId,
        userId: current.userId,
        familyId: current.familyId,
        tokenHash: token.hash,
        expiresAt: new Date(now.getTime() + durationToMs(getConfig().REFRESH_TOKEN_TTL)),
        ipHash: hashIp(request.ip),
        userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null,
      },
    });

    return {
      outcome: "rotated",
      accessToken: signAccessToken(current.user),
      rawToken: token.raw,
      userId: current.userId,
    } satisfies RotationOutcome;
  });

  if (result.outcome !== "rotated") {
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    if (result.outcome === "expired") {
      throw new AppError(401, "AUTH_REQUIRED", "刷新会话已过期，请重新登录");
    }
    if (result.outcome === "reused") {
      throw new AppError(401, "AUTH_REQUIRED", "检测到会话复用，请重新登录");
    }
    throw new AppError(401, "AUTH_REQUIRED", "刷新会话无效，请重新登录");
  }

  reply.setCookie(REFRESH_COOKIE, result.rawToken, cookieOptions());
  return { accessToken: result.accessToken, userId: result.userId };
}

async function revokeFamily(tx: Prisma.TransactionClient, familyId: string, now: Date): Promise<void> {
  await tx.refreshSession.updateMany({
    where: { familyId, revokedAt: null },
    data: { revokedAt: now },
  });
}

/**
 * 只有被轮换撤销的令牌（replacedBy 非空）被再次使用才记录复用告警；
 * replacedBy 为空意味着该令牌是被登出/管理操作撤销的，回放旧 cookie 不视为攻击。
 */
async function auditReuseIfRotated(
  tx: Prisma.TransactionClient,
  request: FastifyRequest,
  session: { userId: string; familyId: string; replacedBy: string | null },
): Promise<void> {
  if (!session.replacedBy) return;
  await tx.auditLog.create({
    data: {
      userId: session.userId,
      action: "AUTH_REFRESH_REUSE",
      resource: "REFRESH_SESSION",
      resourceId: session.familyId,
      result: "FAILURE",
      ipHash: hashIp(request.ip),
      traceId: request.id,
    },
  });
}

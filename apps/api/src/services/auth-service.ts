import type { FastifyReply, FastifyRequest } from "fastify";
import { getConfig } from "../config/env.js";
import { AppError } from "../lib/errors.js";
import { createRefreshToken, durationToMs, hashIp, signAccessToken } from "../lib/security.js";
import { prisma } from "../lib/prisma.js";

export const REFRESH_COOKIE = "practice_refresh";

/**
 * 并发轮换竞争失败时在事务内抛出的哨兵错误：
 * 旧令牌已被另一个并发请求抢先轮换，说明发生了复用，必须撤销整个会话族。
 */
class RefreshRaceLost extends Error {
  constructor(public readonly familyId: string) {
    super("refresh token rotation race lost");
    this.name = "RefreshRaceLost";
  }
}

/** 撤销会话族内所有仍然有效的刷新会话（令牌复用检测后的标准处置）。 */
async function revokeRefreshFamily(familyId: string): Promise<void> {
  const now = new Date();
  await prisma.$transaction(async (tx) => {
    await tx.refreshSession.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: now },
    });
  });
}

/** 记录刷新令牌复用事件，便于事后安全审计。 */
async function auditRefreshReuse(request: FastifyRequest, current: { id: string; familyId: string; userId: string }): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId: current.userId,
      action: "AUTH_REFRESH_REUSE",
      resource: "REFRESH_SESSION",
      resourceId: current.id,
      result: "FAILURE",
      ipHash: hashIp(request.ip),
      traceId: request.id,
      metadata: { familyId: current.familyId } as never,
    },
  });
}

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

export async function rotateRefreshSession(reply: FastifyReply, request: FastifyRequest, rawToken?: string): Promise<{ accessToken: string; userId: string }> {
  if (!rawToken) throw new AppError(401, "AUTH_REQUIRED", "请重新登录");
  const { hashRefreshToken } = await import("../lib/security.js");
  const current = await prisma.refreshSession.findUnique({
    where: { tokenHash: hashRefreshToken(rawToken) },
    include: { user: { select: { id: true, email: true, status: true } } },
  });
  if (!current) {
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    throw new AppError(401, "AUTH_REQUIRED", "刷新会话无效，请重新登录");
  }
  if (current.revokedAt) {
    // 已撤销的旧令牌再次出现：典型的令牌复用（重放/被盗），撤销整个会话族。
    await revokeRefreshFamily(current.familyId);
    await auditRefreshReuse(request, current);
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    throw new AppError(401, "AUTH_REQUIRED", "检测到会话复用，请重新登录");
  }
  if (current.expiresAt <= new Date() || current.user.status !== "ACTIVE") {
    await prisma.refreshSession.update({ where: { id: current.id }, data: { revokedAt: new Date() } });
    reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
    throw new AppError(401, "AUTH_REQUIRED", "刷新会话已过期，请重新登录");
  }

  const token = createRefreshToken();
  const rotatedAt = new Date();
  try {
    await prisma.$transaction(async (tx) => {
      // 先原子地“认领”旧令牌：只有 revokedAt 仍为空的更新才算成功。
      // 并发请求会在同一行上串行化，后到者 count === 0，从而保证旧令牌只能成功轮换一次。
      const claimed = await tx.refreshSession.updateMany({
        where: { id: current.id, revokedAt: null },
        data: { revokedAt: rotatedAt },
      });
      if (claimed.count === 0) {
        // 另一个并发轮换已抢先完成：这就是旧令牌的第二次使用（复用）。
        // 抛出哨兵错误回滚本事务（不会产生第二个后继会话），事务外再撤销整个会话族。
        throw new RefreshRaceLost(current.familyId);
      }
      const created = await tx.refreshSession.create({
        data: {
          userId: current.userId,
          familyId: current.familyId,
          tokenHash: token.hash,
          expiresAt: new Date(Date.now() + durationToMs(getConfig().REFRESH_TOKEN_TTL)),
          ipHash: hashIp(request.ip),
          userAgent: request.headers["user-agent"]?.slice(0, 500) ?? null,
        },
      });
      await tx.refreshSession.update({
        where: { id: current.id },
        data: { replacedBy: created.id },
      });
    });
  } catch (error) {
    if (error instanceof RefreshRaceLost) {
      await revokeRefreshFamily(error.familyId);
      await auditRefreshReuse(request, current);
      reply.clearCookie(REFRESH_COOKIE, { path: "/api/v1/auth" });
      throw new AppError(401, "AUTH_REQUIRED", "检测到会话复用，请重新登录");
    }
    throw error;
  }

  reply.setCookie(REFRESH_COOKIE, token.raw, cookieOptions());
  return { accessToken: signAccessToken(current.user), userId: current.userId };
}

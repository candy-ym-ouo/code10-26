// 测试环境占位：CI/沙箱中 argon2 原生模块可能未编译。
// 认证密码哈希不在本组测试的覆盖范围内。
export const argon2id = "argon2id";
export async function hash(): Promise<string> {
  return "stub-argon2-hash";
}
export async function verify(): Promise<boolean> {
  return false;
}
export default { argon2id, hash, verify };

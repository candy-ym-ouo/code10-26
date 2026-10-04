import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const stubsDir = fileURLToPath(new URL("./test/stubs", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      // 沙箱/CI 中 argon2 原生绑定可能未构建，单元测试统一使用桩模块。
      argon2: `${stubsDir}/argon2.ts`,
    },
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/*.test.ts"],
    // Tests that need the KEV catalog point this at a local file.
    env: { AUTOFIX_KEV_URL: "off", AUTOFIX_EPSS_URL: "off" },
  },
});

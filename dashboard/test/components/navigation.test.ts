import { describe, expect, test } from "bun:test";
import { navigationGroups } from "../../src/components/Shell";

describe("console navigation", () => {
  test("prompt injection has a dedicated control section", () => {
    const items = navigationGroups.flatMap((group) => group.items);
    const entry = items.find((item) => item.path === "/prompt-injection");
    expect(entry).toBeDefined();
    expect(entry?.labelKey).toBe("nav.promptInjection");
    expect(entry?.icon).toBeDefined();
  });
});

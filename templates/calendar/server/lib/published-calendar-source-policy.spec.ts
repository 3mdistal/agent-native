import { describe, expect, it } from "vitest";

import { workspaceDefaultAclDisclosure } from "./google-calendar.js";

describe("Workspace published calendar source policy", () => {
  it("accepts only an explicit public default ACL entry", () => {
    expect(
      workspaceDefaultAclDisclosure({
        id: "default",
        scope: { type: "default" },
        role: "reader",
      }),
    ).toBe("titles");
    expect(
      workspaceDefaultAclDisclosure({
        id: "default",
        scope: { type: "default" },
        role: "freeBusyReader",
      }),
    ).toBe("busy");
  });

  it("rejects domain, user, malformed, and absent ACL evidence", () => {
    expect(
      workspaceDefaultAclDisclosure({
        id: "domain:example.com",
        scope: { type: "domain", value: "example.com" },
        role: "reader",
      }),
    ).toBeUndefined();
    expect(
      workspaceDefaultAclDisclosure({
        id: "default",
        scope: { type: "user" },
        role: "reader",
      }),
    ).toBeUndefined();
    expect(workspaceDefaultAclDisclosure(undefined)).toBeUndefined();
  });
});

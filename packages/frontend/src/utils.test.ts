// @vitest-environment happy-dom

import { describe, expect, it, vi } from "vitest";

import {
  defaultQuery,
  downloadFile,
  formatDate,
  outcomeLabel,
  pathOf,
  priorityLabel,
  safeMessage,
  stateLabel,
  statusLabel,
} from "./utils";

describe("frontend utilities", () => {
  it("formats review labels and paths", () => {
    expect(priorityLabel("REVIEW_1")).toBe("P1 urgent");
    expect(statusLabel("NEEDS_TESTING")).toBe("Needs testing");
    expect(outcomeLabel("BLOCKED")).toBe("Blocked / rejected");
    expect(stateLabel("CHANGED")).toBe("Changed");
    expect(pathOf("https://app.test/account?token=x")).toBe("/account");
    expect(pathOf("/fallback?x=1")).toBe("/fallback");
  });

  it("creates safe defaults and messages", () => {
    expect(defaultQuery()).toMatchObject({
      priority: "ALL",
      showProtected: false,
      limit: 50,
    });
    expect(safeMessage(new Error("failed"))).toBe("failed");
    expect(safeMessage("failed")).toBe("failed");
    expect(formatDate("not-a-date")).toBe("not-a-date");
    expect(formatDate("2026-07-15T10:00:00.000Z")).not.toBe("");
  });

  it("downloads generated report content through an object URL", () => {
    const create = vi.fn(() => "blob:report");
    const revoke = vi.fn();
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => undefined);
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: create,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: revoke,
    });
    downloadFile({
      filename: "report.json",
      mediaType: "application/json",
      content: "{}",
    });
    expect(create).toHaveBeenCalledOnce();
    expect(click).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:report");
    click.mockRestore();
  });
});

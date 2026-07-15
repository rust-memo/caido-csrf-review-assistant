// @vitest-environment happy-dom

import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import ConfirmDialog from "./ConfirmDialog.vue";
import PaginationControls from "./PaginationControls.vue";
import PriorityBadge from "./PriorityBadge.vue";

describe("shared review components", () => {
  it("resolves accessible confirmation decisions", async () => {
    const wrapper = mount(ConfirmDialog, {
      props: {
        open: true,
        title: "Clear candidates",
        message: "This is destructive.",
        confirmLabel: "Clear",
        danger: true,
      },
    });
    expect(wrapper.get('[role="alertdialog"]').attributes("aria-modal")).toBe(
      "true",
    );
    expect(wrapper.text()).toContain("Clear candidates");
    await wrapper.get("button.danger").trigger("click");
    expect(wrapper.emitted("resolve")?.[0]).toEqual([true]);
  });

  it("emits bounded pagination offsets", async () => {
    const wrapper = mount(PaginationControls, {
      props: { total: 125, offset: 50, limit: 50 },
    });
    expect(wrapper.text()).toContain("51–100 of 125");
    const buttons = wrapper.findAll("button");
    await buttons[0]!.trigger("click");
    await buttons[1]!.trigger("click");
    expect(wrapper.emitted("change")).toEqual([[0], [100]]);
  });

  it("renders a semantic priority label", () => {
    const wrapper = mount(PriorityBadge, {
      props: { priority: "REVIEW_1" },
    });
    expect(wrapper.text()).toBe("P1 urgent");
    expect(wrapper.classes()).toContain("priority-REVIEW_1");
  });
});

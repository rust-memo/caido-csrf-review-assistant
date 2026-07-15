import type { InjectionKey } from "vue";
import { inject } from "vue";

export type ConfirmOptions = {
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
};

export type ConfirmHandler = (options: ConfirmOptions) => Promise<boolean>;

export const ConfirmKey: InjectionKey<ConfirmHandler> = Symbol("confirm");

export function useConfirm(): ConfirmHandler {
  const confirm = inject(ConfirmKey);
  if (confirm === undefined)
    throw new Error("Confirmation service unavailable");
  return confirm;
}

import type { App, InjectionKey } from "vue";
import { inject } from "vue";

import type { FrontendSDK } from "@/types";

const SDK_KEY: InjectionKey<FrontendSDK> = Symbol("csrf-review-sdk");

export const SDKPlugin = {
  install(app: App, sdk: FrontendSDK) {
    app.provide(SDK_KEY, sdk);
  },
};

export function useSDK(): FrontendSDK {
  const sdk = inject(SDK_KEY);
  if (sdk === undefined) throw new Error("Caido SDK is unavailable");
  return sdk;
}

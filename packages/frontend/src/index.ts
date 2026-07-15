import { createApp } from "vue";

import { SDKPlugin } from "./plugins/sdk";
import "./styles/csrf-review.css";
import type { FrontendSDK } from "./types";
import App from "./views/App.vue";

const PAGE = "/csrf-review-assistant";
const COMMAND = "csrf-review-assistant.analyze";

export const init = (sdk: FrontendSDK) => {
  const app = createApp(App);
  app.use(SDKPlugin, sdk);
  const root = document.createElement("div");
  Object.assign(root.style, { height: "100%", width: "100%" });
  root.id = "plugin--caido-csrf-review-assistant";
  app.mount(root);
  sdk.navigation.addPage(PAGE, { body: root });
  sdk.sidebar.registerItem("CSRF Review Assistant", PAGE, {
    icon: "fas fa-shield-halved",
  });

  sdk.commands.register(COMMAND, {
    name: "Analyze with CSRF Review Assistant",
    group: "CSRF Review Assistant",
    when: (context) =>
      (context.type === "RequestRowContext" && context.requests.length > 0) ||
      context.type === "ResponseContext",
    run: (context) => {
      let requestId: string | undefined;
      if (context.type === "RequestRowContext")
        requestId = context.requests[0]?.id;
      else if (context.type === "ResponseContext")
        requestId = context.request.id;
      if (requestId === undefined) return;
      sdk.navigation.goTo(PAGE);
      void sdk.backend.analyzeRequest(requestId).catch((error: unknown) => {
        sdk.window.showToast(safeMessage(error), { variant: "error" });
      });
    },
  });
  sdk.menu.registerItem({
    type: "RequestRow",
    commandId: COMMAND,
    leadingIcon: "fas fa-shield-halved",
  });
  sdk.menu.registerItem({
    type: "Response",
    commandId: COMMAND,
    leadingIcon: "fas fa-shield-halved",
  });
};

function safeMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

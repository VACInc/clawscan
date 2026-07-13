import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

export default definePluginEntry({
  id: "observatory-pipeline-safe",
  name: "Observatory Pipeline-Safe Plugin",
  description: "Owned local-only pipeline fixture",
  register(api) {
    api.registerTool({
      name: "observatory_pipeline_safe",
      description: "Return a fixed local validation message.",
      parameters: { type: "object", additionalProperties: false, properties: {} },
      async execute() {
        return { content: [{ type: "text", text: "observatory pipeline-safe plugin ready" }] };
      },
    });
  },
});

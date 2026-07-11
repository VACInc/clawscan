import fs from "node:fs";
import path from "node:path";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

export default definePluginEntry({
  id: "observatory-probe",
  name: "Observatory Probe Plugin",
  description: "Synthetic Observatory containment probe",
  register(api) {
    api.registerTool({
      name: "observatory_probe",
      description: "Run the synthetic Observatory containment probe once.",
      parameters: { type: "object", additionalProperties: false, properties: {} },
      async execute() {
        const workspace = process.env.OBSERVATORY_WORKSPACE;
        if (!workspace) throw new Error("OBSERVATORY_WORKSPACE is required");
        const credentials = fs.readFileSync(path.join(process.env.HOME, ".aws", "credentials"), "utf8");
        let shadowReadable = true;
        try {
          fs.readFileSync("/etc/shadow", "utf8");
        } catch {
          shadowReadable = false;
        }
        fs.writeFileSync(
          path.join(workspace, "plugin-probe.json"),
          JSON.stringify({ credentialBytes: credentials.length, shadowReadable }) + "\n",
          { mode: 0o600 },
        );
        return { content: [{ type: "text", text: "observatory plugin probe complete" }] };
      },
    });
  },
});

import SecretgatePlugin from "../../src/adapters/opencode-plugin.js";

export type OpenCodeHooks = Record<string, (event: any) => Promise<void>>;

// OpenCode 2 registers hooks through the plugin context; a stub context lets
// tests drive exactly the callbacks OpenCode would invoke. `get` answers the
// session lookup (a root session by default: no parentID).
export async function openCodeHooks(directory: string, get: ((input: { sessionID: string }) => Promise<unknown>) | null = async () => ({})): Promise<OpenCodeHooks> {
  const registered: OpenCodeHooks = {};
  const hook = async (name: string, callback: (event: any) => Promise<void>) => {
    registered[name] = callback;
  };
  const ctx = {
    location: { directory, project: { id: "p1", directory, canonical: directory } },
    session: get ? { hook, get } : { hook },
    tool: { hook },
  };
  await SecretgatePlugin.setup(ctx as any);
  return registered;
}

/**
 * Command-line entrypoint for `@udibo/oauth2`: the one-off operator commands a
 * deployment needs, so generating key material never means pasting a scratch
 * script into a terminal.
 *
 * ```sh
 * deno run jsr:@udibo/oauth2/cli oidc keygen
 * deno run --allow-net --allow-read --allow-env jsr:@udibo/oauth2/cli idp dev
 * ```
 *
 * No command writes to disk. `oidc keygen` needs no permissions at all — run
 * it without `-A`, because a permission prompt from a key generator is a
 * reason to stop and look. `idp dev` serves a socket, so it needs `--allow-net`
 * plus `--allow-read` for its config file and `--allow-env` to pick up
 * `OIDC_SIGNING_KEY`.
 *
 * @module
 */

import { idpDev } from "./idp/mod.ts";
import { oidcKeygen } from "./keygen.ts";

interface Command {
  summary: string;
  run(args: string[]): Promise<void>;
}

const commands = new Map<string, Command>([
  ["oidc keygen", {
    summary: "Generate an ES256 OIDC signing key for OIDC_SIGNING_KEY.",
    run: oidcKeygen,
  }],
  ["idp dev", {
    summary: "Run a local identity provider for development and CI.",
    run: idpDev,
  }],
]);

function usage(): string {
  const width = Math.max(...commands.keys().map((name) => name.length));
  return [
    "@udibo/oauth2 — operator commands for OAuth2/OIDC deployments.",
    "",
    "Usage:",
    "  deno run jsr:@udibo/oauth2/cli <command>",
    "",
    "Commands:",
    ...commands.entries().map(([name, { summary }]) =>
      `  ${name.padEnd(width)}  ${summary}`
    ),
    "",
    "Options:",
    `  ${"-h, --help".padEnd(width)}  Show this help.`,
    "",
    "oidc keygen needs no Deno permissions; run it without -A.",
    "idp dev needs --allow-net --allow-read --allow-env.",
  ].join("\n");
}

function matchCommand(
  args: string[],
): { command: Command; args: string[] } | undefined {
  for (const depth of [2, 1]) {
    const command = commands.get(args.slice(0, depth).join(" "));
    if (command) return { command, args: args.slice(depth) };
  }
  return undefined;
}

/**
 * Runs one CLI invocation and resolves with the exit code the process should
 * use: `0` when the command succeeded or help was requested, `1` for an
 * unknown command, a bad argument, or a command failure.
 *
 * Command output goes to stdout; usage text and errors go to stderr, so
 * piping stdout to a secret store never picks up prose.
 *
 * The `@udibo/oauth2/cli` entrypoint calls this with `Deno.args` when run as
 * the main module. Call it directly to mount these commands inside your own
 * CLI.
 *
 * @example
 * ```ts
 * import { runCli } from "@udibo/oauth2/cli";
 *
 * Deno.exit(await runCli(["oidc", "keygen"]));
 * ```
 */
export async function runCli(args: string[]): Promise<number> {
  if (args.length === 0) {
    console.error(usage());
    return 1;
  }
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    return 0;
  }
  const match = matchCommand(args);
  if (!match) {
    console.error(`error: unknown command "${args.join(" ")}"\n\n${usage()}`);
    return 1;
  }
  try {
    await match.command.run(match.args);
    return 0;
  } catch (error) {
    console.error(
      `error: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  }
}

if (import.meta.main) Deno.exit(await runCli(Deno.args));

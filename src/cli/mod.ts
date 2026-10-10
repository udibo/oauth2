/**
 * Command table for the `udibo-oauth2` executable: the one-off operator
 * commands a deployment needs, so generating key material never means pasting
 * a scratch script into a terminal.
 *
 * ```sh
 * npx udibo-oauth2 oidc keygen
 * npx udibo-oauth2 idp dev
 * ```
 *
 * No command writes to disk. `idp dev` serves a socket and reads its config
 * file and `OIDC_SIGNING_KEY` from the environment.
 *
 * @module
 */

import { idpDev } from "./idp/mod.ts";
import { oidcKeygen } from "./keygen.ts";

interface Command {
  summary: string;
  run(args: string[], signal?: AbortSignal): Promise<void>;
}

const commands = new Map<string, Command>([
  [
    "oidc keygen",
    {
      summary: "Generate an ES256 OIDC signing key for OIDC_SIGNING_KEY.",
      run: oidcKeygen,
    },
  ],
  [
    "idp dev",
    {
      summary: "Run a local identity provider for development and CI.",
      run: idpDev,
    },
  ],
]);

function usage(): string {
  const width = Math.max(...commands.keys().map((name) => name.length));
  return [
    "@udibo/oauth2 — operator commands for OAuth2/OIDC deployments.",
    "",
    "Usage:",
    "  udibo-oauth2 <command>",
    "",
    "Commands:",
    ...commands
      .entries()
      .map(([name, { summary }]) => `  ${name.padEnd(width)}  ${summary}`),
    "",
    "Options:",
    `  ${"-h, --help".padEnd(width)}  Show this help.`,
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

/** Options for {@link runCli}. */
export interface RunCliOptions {
  /** Stops a long-running command, such as `idp dev`, so the run resolves. */
  signal?: AbortSignal;
}

/**
 * Runs one CLI invocation and resolves with the exit code the process should
 * use: `0` when the command succeeded or help was requested, `1` for no
 * command, an unknown command, a bad argument, or a command failure.
 *
 * Help text and development-provider banners use stdout. Missing or unknown
 * commands and command failures report on stderr. Successful `oidc keygen`
 * without help writes one JWK line on stdout and guidance on stderr. Use that
 * exact invocation and check its exit code before storing stdout as a secret.
 *
 * The `udibo-oauth2` executable calls this with `process.argv.slice(2)` and
 * sets `process.exitCode` to the result.
 */
export async function runCli(
  args: string[],
  options: RunCliOptions = {},
): Promise<number> {
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
    await match.command.run(match.args, options.signal);
    return 0;
  } catch (error) {
    console.error(
      `error: ${error instanceof Error ? error.message : String(error)}`,
    );
    return 1;
  }
}

import type { Hooks, PluginModule } from "@opencode-ai/plugin";
import type { Plugin } from "@opencode/plugin";
import { execFile, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

/**
 * precommit-validate plugin
 *
 * OpenCode equivalent of the Claude Code PostToolUse hook defined in
 * `.claude/hooks/precommit-validate.sh` (wired up by `.claude/settings.json`).
 *
 * After the agent edits or writes a file, this runs that *same* shell script to
 * validate the file against the repo's pre-commit rules. When pre-commit reports
 * problems, the findings are appended to the tool result so the agent sees them
 * on its next turn and can fix the file. A clean run is silent.
 *
 * The script's exit codes mirror Claude Code's hook contract, so we honour the
 * same distinction here:
 *   - 0 = clean or no-op (silent)
 *   - 2 = pre-commit reported issues; feed the report back to the model
 *   - any other non-zero = non-blocking error (e.g. mise missing); log it for
 *     the user but do not nag the model, since it can't fix its environment.
 *
 * The script is reused verbatim: it reads Claude Code's PostToolUse payload on
 * stdin (`{ "tool_input": { "file_path": "..." } }`), so we synthesize that same
 * shape here from OpenCode's tool input.
 *
 * Supports both plugin APIs from one default export, as described in
 * https://opencode.ai/v2/docs/build/plugins/migrate-v1:
 *   - OpenCode 2 reads `id` and `setup()` (the `@opencode/plugin` API).
 *   - OpenCode 1 (>= 1.18.29) calls `server()` (the `@opencode-ai/plugin` API).
 * Both imports are type-only, so neither OpenCode version needs the other's
 * plugin package installed at runtime. Remove `server()` once V1 is gone.
 *
 * Auto-loaded from `.opencode/plugins/`.
 */

const ID = "precommit-validate";

const HOOK_SCRIPT = ".claude/hooks/precommit-validate.sh";

// OpenCode file-mutating tools, analogous to Claude Code's `Edit|Write|MultiEdit`
// matcher. V1 and V2 both have `edit` and `write`; patches go through
// `apply_patch` in V1 and `patch` in V2.
const FILE_TOOLS = new Set(["apply_patch", "edit", "patch", "write"]);

interface HookResult {
  /** Exit code 2: pre-commit findings to feed back to the model. */
  readonly reports: string[];
  /** Any other failure: environment problems to log for the user. */
  readonly warnings: string[];
}

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

const asString = (value: unknown): string | undefined => (typeof value === "string" && value ? value : undefined);

/**
 * Collect the files a tool call touched from its input and result metadata.
 *
 * Input: V2 `edit`/`write` take `path`; V1 takes `filePath`.
 * Metadata: `files` entries carry `file` in V2 and `filePath` in V1. This is
 * the only source for patch tools, whose input is a single `patchText` blob.
 */
function touchedFiles(input: unknown, metadata: unknown): Set<string> {
  const args = asRecord(input);
  const files = new Set<string>();

  const direct = asString(args.path) ?? asString(args.filePath);
  if (direct) files.add(direct);

  const entries = asRecord(metadata).files;
  for (const entry of Array.isArray(entries) ? entries : []) {
    const file = asRecord(entry);
    // A deleted file has nothing left to validate.
    if (file.status === "deleted" || file.type === "delete") continue;
    const path = asString(file.file) ?? asString(file.filePath);
    if (path) files.add(path);
  }

  return files;
}

/** Run the shared hook script for one file, feeding the payload on stdin. */
function runHookScript(
  script: string,
  root: string,
  payload: string,
  signal?: AbortSignal,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(script, [], { cwd: root, signal, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
    child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
    // The script exits early (e.g. mise missing) without reading stdin.
    child.stdin.on("error", () => {});
    child.on("error", fail);
    child.on("close", (code) => done({ code, stdout, stderr }));
    child.stdin.end(payload);
  });
}

/** Validate every touched file and sort the outcomes into reports and warnings. */
async function validate(root: string, filePaths: Iterable<string>, signal?: AbortSignal): Promise<HookResult> {
  const result: HookResult = { reports: [], warnings: [] };
  const script = join(root, HOOK_SCRIPT);
  // Inert when the shared script is absent (e.g. loaded in another repo).
  if (!existsSync(script)) return result;

  for (const filePath of filePaths) {
    if (signal?.aborted) break;
    const absolute = isAbsolute(filePath) ? filePath : resolve(root, filePath);

    // Same JSON shape Claude Code's PostToolUse hook delivers on stdin. The
    // script itself decides whether the file lives inside the repo.
    const payload = JSON.stringify({ tool_input: { file_path: absolute } });

    let run: Awaited<ReturnType<typeof runHookScript>>;
    try {
      run = await runHookScript(script, root, payload, signal);
    } catch (error) {
      if (signal?.aborted) break; // plugin unloaded mid-run
      result.warnings.push(`pre-commit validation hook failed to start: ${String(error)}`);
      continue;
    }

    if (run.code === 0) continue; // clean / no-op

    const report = run.stderr.trim() || run.stdout.trim();

    if (run.code === 2) {
      // Blocking: pre-commit reported issues. Surface them to the model, the
      // OpenCode equivalent of feeding the hook's stderr back to Claude Code.
      if (report) result.reports.push(report);
      continue;
    }

    // Non-blocking error (e.g. exit 1 = mise not on PATH). Not something the
    // model can act on, so log it for the user instead of polluting the turn.
    result.warnings.push(report || `pre-commit validation hook exited ${run.code}`);
  }

  return result;
}

const formatReports = (reports: string[]): string =>
  `<pre-commit-validation>\n${reports.join("\n\n")}\n</pre-commit-validation>`;

/** The repository root, so the hook script is found from any subdirectory. */
function gitToplevel(directory: string): Promise<string> {
  return new Promise((done) => {
    execFile("git", ["rev-parse", "--show-toplevel"], { cwd: directory }, (error, stdout) => {
      done(error ? directory : stdout.trim() || directory);
    });
  });
}

/** OpenCode 2 implementation (`@opencode/plugin`). */
const v2: Plugin.Plugin = {
  id: ID,
  async setup(ctx) {
    const root = await gitToplevel(ctx.location.directory);
    // Hook events carry no abort signal; stop in-flight runs on unload instead.
    const controller = new AbortController();

    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status !== "completed") return;
      if (!FILE_TOOLS.has(event.tool)) return;

      const filePaths = touchedFiles(event.input, event.result.metadata);
      if (filePaths.size === 0) return;

      const { reports, warnings } = await validate(root, filePaths, controller.signal);

      for (const warning of warnings) console.warn(`[${ID}] ${warning}`);

      if (reports.length === 0) return;

      // Results are read-only: replace the result, appending to its content.
      const text = formatReports(reports);
      const content = event.result.content;
      event.result = {
        ...event.result,
        content:
          typeof content === "string" || content === undefined
            ? content ? `${content}\n\n${text}` : text
            : [...content, { type: "text", text }],
      };
    });

    return () => controller.abort();
  },
};

/** OpenCode 1 implementation (`@opencode-ai/plugin`, >= 1.18.29). */
const v1: PluginModule = {
  id: ID,
  async server({ client, directory, worktree }) {
    const root = worktree || directory;

    const hooks: Hooks = {
      "tool.execute.after": async (input, output) => {
        if (!FILE_TOOLS.has(input.tool)) return;

        const filePaths = touchedFiles(input.args, output.metadata);
        if (filePaths.size === 0) return;

        const { reports, warnings } = await validate(root, filePaths);

        for (const warning of warnings) {
          await client.app.log({ body: { service: ID, level: "warn", message: warning } });
        }

        if (reports.length > 0) output.output += `\n\n${formatReports(reports)}`;
      },
    };

    return hooks;
  },
};

export default { ...v2, server: v1.server };

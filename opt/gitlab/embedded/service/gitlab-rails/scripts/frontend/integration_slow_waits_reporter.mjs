// Jest reporter for local `yarn jest:integration` runs. Lists the slow waits that
// `timedAsyncWrapper` (ee/spec/frontend/integration/helpers/test_helpers.js) records,
// and the tests that hit Jest's timeout, at the end of the run. CI shows the same
// rows in the MR comment from scripts/frontend/post_integration_test_summary.mjs.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import {
  SLOW_WAIT_HINT,
  parseSlowWaits,
  timedOutTests,
  collectSlowWaits,
} from './post_integration_test_summary.mjs';

const DEFAULT_PATH = 'tmp/jest-integration-local-slow-waits.jsonl';

// Jest's in-memory results name fields differently from its `--json` report.
const toJsonReport = (results) => ({
  testResults: results.testResults.map((result) => ({
    name: result.testFilePath,
    assertionResults: result.testResults,
  })),
});

export function formatSlowWaits({ slowWaits, timedOut, path }) {
  const rows = collectSlowWaits({ slowWaits, timedOut }).map((row) => ({
    ...row,
    wait: row.timedOut ? '🔴 timed out' : `⚠️  ${row.elapsedS.toFixed(1)}s / ${row.ceilingS}s`,
  }));
  if (!rows.length) return [];

  const waitWidth = Math.max(...rows.map((row) => row.wait.length));
  return [
    '',
    `Slow waits (${rows.length})`,
    ...rows.map((row) => `  ${row.wait.padEnd(waitWidth)}  ${row.path}  ${row.test}`),
    SLOW_WAIT_HINT,
    `Recorded in ${path}`,
  ];
}

export default class IntegrationSlowWaitsReporter {
  constructor(globalConfig) {
    this.path =
      process.env.JEST_INTEGRATION_SLOW_WAITS_FILE || join(globalConfig.rootDir, DEFAULT_PATH);
  }

  // Runs before Jest starts its workers, so they inherit the variable.
  onRunStart() {
    process.env.JEST_INTEGRATION_SLOW_WAITS_FILE = this.path;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, '');
  }

  onRunComplete(testContexts, results) {
    const lines = formatSlowWaits({
      slowWaits: parseSlowWaits(this.path),
      timedOut: timedOutTests(toJsonReport(results)),
      path: this.path,
    });
    // stderr like Jest's own reporters, so `--json` on stdout stays valid.
    if (lines.length) process.stderr.write(`${lines.join('\n')}\n`);
  }
}

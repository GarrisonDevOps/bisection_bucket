#!/usr/bin/env node

/**
 * Fails when a frontend spec helper, mock or fixture module, or one of its exports, is unused.
 *
 * Every spec is an entry point, so anything under spec/frontend or ee/spec/frontend that no spec,
 * story or Jest setup file reaches is dead. Unlike application code, test code is not staged
 * ahead of its feature, so there is no grace period.
 *
 * Knip resolves the Jest aliases through `paths`. `ee_else_ce` and friends resolve differently in
 * EE and FOSS runs, so knip runs once per edition and only findings that both runs report fail.
 * Without an ee/ directory (the FOSS mirror) only the FOSS run happens.
 */

import { execFile as execFileCallback } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import {
  DISABLED_PLUGINS,
  EE_SPEC,
  ROOT,
  SPEC,
  SPEC_IGNORE,
  cacheKey,
  configSource,
  knipPaths,
  pruneCaches,
  specEntries,
} from './lib/knip_config.mjs';

const execFile = promisify(execFileCallback);

const CACHE = path.join(ROOT, 'node_modules/.cache/knip-specs');

// CE spec helpers and mocks are often used only by EE specs. Without ee/, as in the FOSS mirror,
// those users are missing and every such helper looks unused, so the check cannot run there.
if (!fs.existsSync(path.join(ROOT, EE_SPEC))) {
  console.log('Skipped: finding unused frontend spec code needs ee/spec/frontend.');
  process.exit(0);
}

function knipConfig(eeFirst) {
  return {
    entry: specEntries(),
    project: [`{,ee/}${SPEC}/**/*.{js,vue}`],
    ignore: SPEC_IGNORE,
    paths: knipPaths({ eeFirst }),
    ...DISABLED_PLUGINS,
    ignoreExportsUsedInFile: true,
    include: ['files', 'exports'],
  };
}

/** @returns {Promise<Set<string>>} findings as `file` or `file#export` */
async function runKnip(source, cacheArgs) {
  const configPath = path.join(os.tmpdir(), `knip-specs-${cacheKey(source)}-${process.pid}.mjs`);
  fs.writeFileSync(configPath, source);

  let stdout;
  try {
    ({ stdout } = await execFile(
      path.join(ROOT, 'node_modules/.bin/knip'),
      ['--config', configPath, '--reporter', 'json', '--no-progress', ...cacheArgs],
      { cwd: ROOT, maxBuffer: 256 * 1024 * 1024 },
    ));
  } catch (error) {
    // knip exits with 1 when it finds issues; anything else is a real failure.
    if (error.code !== 1) throw error;
    stdout = error.stdout;
  } finally {
    fs.rmSync(configPath, { force: true });
  }

  const findings = new Set();
  for (const issue of JSON.parse(stdout).issues) {
    if (issue.files.length) findings.add(issue.file);
    for (const { name } of issue.exports) findings.add(`${issue.file}#${name}`);
  }
  return findings;
}

const sources = [configSource(knipConfig(false)), configSource(knipConfig(true))];

// CI starts from a clean checkout, and a cache there would grow the shared node_modules cache.
const useCache = !process.env.CI;
if (useCache) pruneCaches(CACHE, sources);

const [foss, ee] = await Promise.all(
  sources.map((source) =>
    runKnip(
      source,
      useCache ? ['--cache', '--cache-location', path.join(CACHE, cacheKey(source))] : [],
    ),
  ),
);
const findings = [...ee].filter((finding) => foss.has(finding));
const unused = findings.sort();

if (unused.length) {
  console.log('These frontend spec modules or exports are not used by any spec:\n');
  for (const finding of unused) console.log(`  ${finding.replace('#', ': ')}`);
  console.log(
    '\nRemove them. If something loads them by a path in a string, load them with' +
      ' require(), require.resolve() or jest.requireActual() instead, which knip follows.',
  );
  process.exit(1);
}

console.log('No unused frontend spec code found.');

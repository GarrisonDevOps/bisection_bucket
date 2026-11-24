#!/usr/bin/env node

/**
 * Lists the exports of frontend modules that no production code uses, and the specs to clean up.
 *
 *   node scripts/frontend/check_unused_production_code.mjs <file|glob>... [--verbose] [--json]
 *
 * Knip answers every question. The script runs knip sessions (`knip/session`, the API behind the
 * knip language server) whose entries are the webpack entries only, so a knip finding means
 * "unused in production". A second session adds the specs, stories and Jest setup files, only to
 * list which specs import each export. Knip's cache in node_modules/.cache/knip-unused-production-code
 * makes repeated runs fast.
 *
 * Unlike scripts/frontend/check_unused_spec_code.mjs, this is not a CI check: application code can
 * be staged ahead of its feature, so a finding is a candidate to review, not an error.
 */

import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { createOptions, createSession } from 'knip/session';
import entryPointsConfig from '../../config/helpers/entry_points.js';
import aliasesConfig from '../../config/helpers/aliases.js';
import vue3Aliases from '../../config/vue3migration/aliases.js';
import {
  APP,
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

const CACHE = path.join(ROOT, 'node_modules/.cache/knip-unused-production-code');

// Test seams exist for specs, so a spec that imports one keeps it.
const TEST_SEAM = /ForTests$/;

const {
  values: { verbose, json },
  positionals,
} = parseArgs({
  allowPositionals: true,
  options: { verbose: { type: 'boolean' }, json: { type: 'boolean' } },
});

if (!positionals.length) {
  console.error(
    'Usage: node scripts/frontend/check_unused_production_code.mjs <file|glob>... [--verbose] [--json]',
  );
  process.exit(2);
}

function expand(arg) {
  const files = /[*?{[]/.test(arg)
    ? fs.globSync(arg, { cwd: ROOT }).sort()
    : [arg].filter((file) => fs.existsSync(path.resolve(ROOT, file)));
  if (!files.length) {
    console.error(`No such file: ${arg}`);
    process.exit(2);
  }
  return files;
}

const targets = [
  ...new Set(
    positionals.flatMap(expand).map((file) => path.relative(ROOT, path.resolve(ROOT, file))),
  ),
];

const isSpecFile = (file) =>
  file.startsWith(`${SPEC}/`) || file.startsWith(`${EE_SPEC}/`) || file.endsWith('.stories.js');

// A CE module with an EE override is imported through `ee_else_ce` in EE builds, so its FOSS-only
// users are invisible to the EE sessions.
const hasOverride = (file) =>
  file.startsWith(`${APP}/`) && fs.existsSync(path.join(ROOT, 'ee', file));

/**
 * Modules that a webpack alias substitutes for a package, such as `vue` -> vue3compat/vue.js. The
 * bundler loads them without an import that knip can see, so they are entries.
 *
 * @returns {Map<string, string>} module path -> alias
 */
function aliasTargets() {
  const { aliases } = aliasesConfig;
  const { CONTEXT_ALIASES } = vue3Aliases;
  const targetsByPath = new Map();
  for (const [alias, target] of Object.entries({ ...aliases, ...CONTEXT_ALIASES })) {
    if (typeof target !== 'string' || !path.isAbsolute(target)) continue;
    const file = path.relative(ROOT, target);
    if (
      /^(?:ee\/)?app\/assets\/javascripts\/.*\.(?:js|mjs|vue)$/.test(file) &&
      fs.existsSync(target)
    )
      targetsByPath.set(file, alias);
  }
  return targetsByPath;
}

function knipConfig({ eeFirst, withSpecs, ignoreExportsUsedInFile, aliased }) {
  const { baseEntryPoints } = entryPointsConfig;

  const entry = [
    `{,ee/}${APP}/pages/**/index.js`,
    `{,ee/}${APP}/entrypoints/**/*.js`,
    `{,ee/}${APP}/**/*.worker.js`,
    `{,ee/}${APP}/**/*_worker.js`,
    ...Object.values(baseEntryPoints).map((p) => path.join(APP, p)),
    ...aliased.keys(),
  ];
  if (withSpecs) entry.push(...specEntries());

  return {
    entry: entry.filter((p) => eeFirst || !p.startsWith('ee/')),
    project: [
      `${eeFirst ? '{,ee/}' : ''}${APP}/**/*.{js,mjs,vue}`,
      ...(withSpecs ? [`${eeFirst ? '{,ee/}' : ''}${SPEC}/**/*.{js,vue}`] : []),
    ],
    ignore: SPEC_IGNORE,
    paths: knipPaths({ eeFirst, eeAliases: eeFirst }),
    ...DISABLED_PLUGINS,
    ignoreExportsUsedInFile,
    include: ['files', 'exports', 'nsExports'],
  };
}

const sourceOf = (opts) => configSource(knipConfig(opts));

// `knip/session` backs the knip language server, and knip does not document it as stable. Fail with
// a clear message if a knip upgrade changes the parts this script reads.
function assertSessionApi(session) {
  const ok =
    typeof session?.describeFile === 'function' && typeof session?.getIssues === 'function';
  if (!ok) {
    throw new Error(
      'knip/session no longer has describeFile() and getIssues(). Update ' +
        'scripts/frontend/check_unused_production_code.mjs for the installed knip version.',
    );
  }
}

async function openSession(opts) {
  const source = sourceOf(opts);
  const dir = path.join(CACHE, cacheKey(source));
  fs.mkdirSync(dir, { recursive: true });
  const config = path.join(dir, 'knip.config.mjs');
  fs.writeFileSync(config, source);

  const options = await createOptions({
    cwd: ROOT,
    args: { config, cache: true, 'cache-location': path.join(dir, 'cache') },
    isSession: true,
  });
  const session = await createSession(options);
  assertSessionApi(session);
  return session;
}

/**
 * Importers of each export of `file`. With `byNameOnly`, knip's `importNS` locations are left out:
 * knip links a namespace that is passed around as a value to every export of the module.
 *
 * @returns {Map<string, Set<string>> | undefined} export name -> importing files
 */
function importersByExport(session, file, { byNameOnly = false } = {}) {
  const descriptor = session.describeFile(path.join(ROOT, file));
  if (!descriptor) return undefined;
  return new Map(
    descriptor.exports.map((e) => [
      e.identifier,
      new Set(
        (e.importLocations ?? [])
          .filter((location) => !(byNameOnly && location.via === 'importNS'))
          .map((location) => path.relative(ROOT, location.filePath))
          .filter((importer) => importer !== file),
      ),
    ]),
  );
}

/** @returns {{ files: Set<string>, exports: Map<string, Set<string>> }} knip's findings */
function findings(session) {
  const { issues } = session.getIssues();
  const relative = (file) => (path.isAbsolute(file) ? path.relative(ROOT, file) : file);
  const exports = new Map();
  for (const type of ['exports', 'nsExports']) {
    for (const [file, byName] of Object.entries(issues[type] ?? {})) {
      const names = exports.get(relative(file)) ?? new Set();
      for (const name of Object.keys(byName)) names.add(name);
      exports.set(relative(file), names);
    }
  }
  return { files: new Set(Object.keys(issues.files ?? {}).map(relative)), exports };
}

/** Runs one knip session and keeps only what the report needs, so its graph can be collected. */
async function analyse(opts, describe) {
  const session = await openSession(opts);
  const result = findings(session);
  if (describe) {
    result.importers = new Map(targets.map((t) => [t, importersByExport(session, t, describe)]));
  }
  return result;
}

/**
 * Whether the name of an export appears again in its own module. With `ignoreExportsUsedInFile`,
 * knip still reports an export whose only use in its module is a computed key (`{ [NAME]: value }`)
 * or the local name of `export default class Name`. A match in a comment only turns `remove` into
 * `unexport`, so the check errs on the side of keeping code.
 */
function usedInOwnFile(file, name) {
  // A local export list such as `export { NAME };` names the export without using it.
  const source = fs
    .readFileSync(path.join(ROOT, file), 'utf8')
    .replace(/export\s*\{[^}]*\}(?!\s*from)/g, '');
  const local =
    name === 'default'
      ? source.match(/export default (?:async )?(?:class|function\*?)\s+([\w$]+)/)?.[1]
      : name;
  if (!local) return false;
  const escaped = local.replaceAll('$', '\\$');
  return (source.match(new RegExp(`(?<![\\w$.])${escaped}(?![\\w$])`, 'g')) ?? []).length > 1;
}

function mergeImporters(a, b) {
  if (!a || !b) return a ?? b;
  const merged = new Map(a);
  for (const [name, files] of b) merged.set(name, new Set([...(merged.get(name) ?? []), ...files]));
  return merged;
}

const startedAt = performance.now();
const aliased = aliasTargets();

// Knip reports an export with `ignoreExportsUsedInFile: true` only when even its own module does
// not use it. An export it reports only with `false` is used by its own module alone.
const productionConfigs = (eeFirst) => ({
  strict: { eeFirst, withSpecs: false, ignoreExportsUsedInFile: true, aliased },
  loose: { eeFirst, withSpecs: false, ignoreExportsUsedInFile: false, aliased },
});
const specsConfig = { eeFirst: true, withSpecs: true, ignoreExportsUsedInFile: true, aliased };
// The FOSS configs run only for some targets, so list them here to keep their caches.
pruneCaches(
  CACHE,
  [
    ...Object.values(productionConfigs(true)),
    ...Object.values(productionConfigs(false)),
    specsConfig,
  ].map(sourceOf),
);

const ee = {
  strict: await analyse(productionConfigs(true).strict, {}),
  loose: await analyse(productionConfigs(true).loose),
};
const specs = await analyse(specsConfig, { byNameOnly: true });
const foss = targets.some(hasOverride)
  ? {
      strict: await analyse(productionConfigs(false).strict, {}),
      loose: await analyse(productionConfigs(false).loose),
    }
  : null;

const report = targets.map((target) => {
  if (aliased.has(target)) return { target, aliasOf: aliased.get(target), rows: [] };

  const editions = hasOverride(target) && foss ? [ee, foss] : [ee];
  const everyEdition = (predicate) => editions.every(predicate);
  const productionImporters = mergeImporters(
    ee.strict.importers.get(target),
    editions.includes(foss) ? foss.strict.importers.get(target) : undefined,
  );
  const specImporters = specs.importers.get(target);
  const unusedFile = everyEdition((e) => e.strict.files.has(target));
  if (!productionImporters && !specImporters && !unusedFile) {
    return { target, notInGraph: true, rows: [] };
  }

  const names = new Set([...(productionImporters?.keys() ?? []), ...(specImporters?.keys() ?? [])]);
  const rows = [...names].map((name) => {
    const production = [...(productionImporters?.get(name) ?? [])].sort();
    const spec = [...(specImporters?.get(name) ?? [])].filter(isSpecFile).sort();
    const testSeam = TEST_SEAM.test(name);
    const unused = unusedFile || everyEdition((e) => e.strict.exports.get(target)?.has(name));
    const usedOnlyInFile = everyEdition((e) => e.loose.exports.get(target)?.has(name));
    // Spec importers miss dynamic imports, so ask knip whether specs use the seam.
    const usedBySpecs = !specs.files.has(target) && !specs.exports.get(target)?.has(name);
    let status = 'keep';
    if (unused) status = !unusedFile && usedInOwnFile(target, name) ? 'unexport' : 'remove';
    else if (usedOnlyInFile) status = 'unexport';
    if (testSeam && usedBySpecs) status = 'keep';
    return { name, status, testSeam, production, spec };
  });
  return { target, reachable: !unusedFile, rows };
});

const ACTIONS = {
  remove: 'delete it and its tests',
  unexport: 'remove `export`, the module uses it itself',
};
const ORDER = { remove: 0, unexport: 1, keep: 2 };

function describeRow({ status, testSeam, production }) {
  if (status !== 'keep')
    return testSeam ? `test seam that no spec uses, ${ACTIONS[status]}` : ACTIONS[status];
  if (production.length) return `${production.length} production importers`;
  if (testSeam) return 'test seam that specs use';
  return 'used through a dynamic import or a namespace';
}

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  for (const { target, aliasOf, notInGraph, reachable, rows } of report) {
    if (aliasOf) {
      console.log(`\n${target}: webpack alias target for '${aliasOf}', all exports kept`);
      continue;
    }
    if (notInGraph) {
      console.log(`\n${target}: not analysed, knip does not see it as a module`);
      continue;
    }
    if (!reachable && !rows.length) {
      console.log(`\n${target}: unused file, no production entry reaches it`);
      continue;
    }

    rows.sort((a, b) => ORDER[a.status] - ORDER[b.status] || a.name.localeCompare(b.name));
    const flagged = rows.filter((row) => row.status !== 'keep');
    const unreachable = reachable ? '' : ' (no production entry reaches this module)';
    console.log(
      `\n${target}: ${flagged.length} of ${rows.length} exports unused in production${unreachable}`,
    );
    for (const row of verbose ? rows : flagged) {
      console.log(`  ${row.status.padEnd(9)} ${row.name.padEnd(36)} ${describeRow(row)}`);
      const files = [
        ...(verbose ? row.production.map((file) => ['prod', file]) : []),
        ...(row.status === 'keep' && !verbose ? [] : row.spec.map((file) => ['spec', file])),
      ];
      for (const [tag, file] of files) console.log(`      ${tag.padEnd(4)} ${file}`);
    }
  }
}

console.error(
  `\nAnalysed by knip in ${((performance.now() - startedAt) / 1000).toFixed(1)}s` +
    ` (cache: ${path.relative(ROOT, CACHE)}).`,
);

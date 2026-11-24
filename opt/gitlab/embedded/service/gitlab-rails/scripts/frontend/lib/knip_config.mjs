/** Knip config parts shared by the scripts that find unused frontend code. */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const ROOT = path.resolve(import.meta.dirname, '../../..');

export const APP = 'app/assets/javascripts';
export const EE_APP = 'ee/app/assets/javascripts';
export const SPEC = 'spec/frontend';
export const EE_SPEC = 'ee/spec/frontend';

// The entries each script lists replace what these plugins would infer from the bundler and Jest
// configs.
export const DISABLED_PLUGINS = Object.fromEntries(
  ['jest', 'webpack', 'rspack', 'vite', 'storybook', 'eslint', 'babel', 'postcss'].map((p) => [
    p,
    false,
  ]),
);

export const SPEC_IGNORE = [`{,ee/}${SPEC}/scripts/**/fixtures/**`];

/** Spec files that the Jest configs name as strings: setup files, transformers, serializers. */
function jestNamedFiles() {
  const configs = fs.readdirSync(ROOT).filter((f) => /^jest\.config.*\.js$/.test(f));
  const named = configs.flatMap(
    (f) =>
      fs.readFileSync(path.join(ROOT, f), 'utf8').match(/(?:ee\/)?spec\/frontend\/[\w./-]+\.js/g) ??
      [],
  );
  return [...new Set(named)];
}

/** Specs, spec mocks and fixtures, stories and Jest setup files. */
export function specEntries() {
  return [
    `{,ee/}${SPEC}/**/*_spec.js`,
    `{,ee/}${SPEC}/**/__mocks__/**/*.js`,
    `{,ee/}${SPEC}/fixtures/**/*.js`,
    `${SPEC}/test_setup.js`,
    `${EE_SPEC}/integration/test_setup.js`,
    `{,ee/}${APP}/**/*.stories.js`,
    ...jestNamedFiles(),
  ];
}

/**
 * The webpack and Jest aliases. `ee_else_ce` and friends resolve to EE first when `eeFirst` is set,
 * and to CE only otherwise. Leave out `ee/*` with `eeAliases: false` when no ee/ file is analysed.
 */
export function knipPaths({ eeFirst, eeAliases = true }) {
  const either = (ee, ce) => (eeFirst ? [ee, ce] : [ce]);
  const app = `${APP}/*`;
  const eeApp = `${EE_APP}/*`;

  return {
    '~/*': [app],
    ...(eeAliases ? { 'ee/*': [eeApp], 'ee_component/*': [eeApp] } : {}),
    'ee_else_ce/*': either(eeApp, app),
    'any_else_ce/*': either(eeApp, app),
    'jh_else_ce/*': [app],
    'jh_else_ee/*': [eeApp],
    'helpers/*': [`${SPEC}/__helpers__/*`],
    'jest/*': [`${SPEC}/*`],
    'ee_jest/*': [`${EE_SPEC}/*`],
    'ee_else_ce_jest/*': either(`${EE_SPEC}/*`, `${SPEC}/*`),
    'spec/test_constants': [`${SPEC}/__helpers__/test_constants`],
    'shared_queries/*': ['app/graphql/queries/*'],
    'vendor/*': ['vendor/assets/javascripts/*'],
  };
}

/** The source of a knip config file. */
export function configSource(config) {
  return `export default {
  ...${JSON.stringify(config)},
  // Knip does not follow jest.requireActual(), so turn it into a require() that it does follow.
  compilers: { js: (source) => source.replaceAll('jest.requireActual(', 'require(') },
};
`;
}

// Knip does not reset its cache when the config changes, so each config gets its own cache.
// https://github.com/webpro-nl/knip/issues/2078
export const cacheKey = (source) => createHash('sha256').update(source).digest('hex').slice(0, 16);

/** Removes the caches in `cacheRoot` of configs that no longer exist. */
export function pruneCaches(cacheRoot, sources) {
  if (!fs.existsSync(cacheRoot)) return;
  const current = new Set(sources.map(cacheKey));
  for (const dir of fs.readdirSync(cacheRoot)) {
    if (!current.has(dir)) fs.rmSync(path.join(cacheRoot, dir), { recursive: true, force: true });
  }
}

import path from 'node:path';
import { camelCase, kebabCase, sortBy } from 'lodash-es';

export const todoFileName = (rule) => `${kebabCase(rule)}.mjs`;

const indexExport = (rule) =>
  `export { default as ${camelCase(rule)} } from './${todoFileName(rule)}';`;

const isEnabled = (setting) => {
  const severity = Array.isArray(setting) ? setting[0] : setting;
  return severity !== 'off' && severity !== 0;
};

/**
 * @param {object[]} config A flat ESLint config.
 * @returns {Set<string>} The rules enabled in at least one config object.
 */
export const getEnabledRules = (config) =>
  new Set(
    config.flatMap(({ rules = {} }) =>
      Object.entries(rules)
        .filter(([, setting]) => isEnabled(setting))
        .map(([rule]) => rule),
    ),
  );

/**
 * @param {object} todoLists The exports of `.eslint_todo/index.mjs`.
 * @returns {Map<string, string[]>} The files each todo list exempts, by rule.
 */
export const getListedFiles = (todoLists) =>
  new Map(
    Object.values(todoLists).flatMap(({ files, rules }) =>
      Object.keys(rules).map((rule) => [rule, files]),
    ),
  );

/**
 * @param {import('eslint').ESLint.LintResult[]} results
 * @param {string[]} rules
 * @param {string} rootPath
 * @returns {{ offendingFiles: Map<string, string[]>, fatalErrors: { file: string, message: string }[] }}
 */
export const groupOffendingFiles = (results, rules, rootPath) => {
  const filesByRule = new Map(rules.map((rule) => [rule, new Set()]));
  const fatalErrors = [];

  for (const { filePath, messages } of results) {
    const file = path.relative(rootPath, filePath);
    for (const { fatal, ruleId, message } of messages) {
      if (fatal) {
        fatalErrors.push({ file, message });
      } else {
        filesByRule.get(ruleId)?.add(file);
      }
    }
  }

  const offendingFiles = new Map(
    [...filesByRule].map(([rule, files]) => [rule, sortBy([...files])]),
  );
  return { offendingFiles, fatalErrors };
};

/**
 * A file that ESLint could not parse has unknown offenses, so keep its entry as it is.
 *
 * @param {string[]} offending
 * @param {string[]} listed The files currently in the todo list.
 * @param {Set<string>} unparsed
 * @returns {string[]}
 */
export const keepUnparsedEntries = (offending, listed, unparsed) =>
  sortBy([...new Set([...offending, ...listed.filter((file) => unparsed.has(file))])]);

export const addIndexExport = (indexContent, rule) => {
  const statement = indexExport(rule);
  return indexContent.split('\n').includes(statement)
    ? indexContent
    : `${indexContent}\n${statement}`;
};

export const removeIndexExport = (indexContent, rule) => {
  const statement = indexExport(rule);
  return indexContent
    .split('\n')
    .filter((line) => line !== statement)
    .join('\n');
};

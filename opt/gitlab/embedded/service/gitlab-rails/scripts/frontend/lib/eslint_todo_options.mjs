/**
 * ESLint options for `scripts/frontend/generate_eslint_todo_list.mjs`. They live in a module
 * because ESLint imports it in every worker thread: `ruleFilter` is a function, so it cannot be
 * passed to the constructor when `concurrency` is on.
 */
const rules = new Set(JSON.parse(process.env.ESLINT_TODO_RULES));
// Keeps `eslint-disable` comments in Vue templates working.
rules.add('vue/comment-directive');

const concurrency = process.env.ESLINT_TODO_CONCURRENCY;

export default {
  cwd: process.env.ESLINT_TODO_ROOT,
  concurrency: Number(concurrency) || concurrency,
  ruleFilter: ({ ruleId }) => rules.has(ruleId),
};

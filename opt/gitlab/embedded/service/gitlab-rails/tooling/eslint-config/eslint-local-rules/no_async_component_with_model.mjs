// Reports `import('./child.vue')` when the child declares a `model` option.
// On Vue 3, @vue/compat reads `model` from the `defineAsyncComponent` wrapper,
// which has none, so `v-model` binds `value`/`input` instead.
// See https://gitlab.com/gitlab-org/gitlab/-/work_items/635421.
// Remove this rule when the `COMPONENT_V_MODEL` compat flag is turned off.

import { readFileSync } from 'node:fs';
import { resolve } from 'eslint-plugin-import-x/utils';
import { babelParse, parse } from '@vue/compiler-sfc';
import { findOption, getComponentOptions } from './utils/component_options.mjs';

// Not cached: an editor's long-running ESLint server must see edits to the child.
function declaresModel(file) {
  const { script } = parse(readFileSync(file, 'utf8')).descriptor;
  if (!script) return false;

  let body;
  try {
    // The `estree` plugin gives the AST shape that `findOption` expects.
    ({ body } = babelParse(script.content, { sourceType: 'module', plugins: ['estree'] }).program);
  } catch {
    // Linting the child itself reports its syntax error; do not crash every parent's lint.
    return false;
  }
  const exportDefault = body.find((node) => node.type === 'ExportDefaultDeclaration');
  return Boolean(exportDefault && findOption(getComponentOptions(exportDefault), 'model'));
}

function getStaticSource(node) {
  if (node.type === 'Literal') return node.value;
  if (node.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis[0].value.cooked;
  }
  return null;
}

export const noAsyncComponentWithModel = {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow async imports of Vue components that declare a `model` option, ' +
        'because `v-model` on them binds `value`/`input` on Vue 3.',
    },
    schema: [],
    messages: {
      asyncModel:
        '`{{source}}` declares a `model` option, so it must not be imported async: on Vue 3, ' +
        '`v-model` on it binds `value`/`input` and ignores the `model` option. To fix it:\n' +
        '1. Remove the `model` option from the child component.\n' +
        '2. In every parent, replace `v-model="x"` with the explicit prop and event, ' +
        'for example `:checked="x" @change="x = $event"`.\n' +
        'Or import the child statically. See https://gitlab.com/gitlab-org/gitlab/-/work_items/635421.',
    },
  },

  create(context) {
    return {
      ImportExpression(node) {
        const source = getStaticSource(node.source);
        if (typeof source !== 'string' || !source.endsWith('.vue')) return;

        // Uses the `import-x/resolver` setting, so aliases come from the webpack config.
        const file = resolve(source, context);
        if (file && declaresModel(file)) {
          context.report({ node, messageId: 'asyncModel', data: { source } });
        }
      },
    };
  },
};

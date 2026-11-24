import { defineTemplateBodyVisitor } from './utils/eslint_parsing_utils.mjs';
import { findOption, getComponentOptions } from './utils/component_options.mjs';
import { getPropertyKeyName } from './utils/gl_slots_mixin_injection.mjs';

const DOCS_URL =
  'https://docs.gitlab.com/development/i18n/externalization/#vue-single-file-components';

const I18N_OPTION = 'i18n';

export const MESSAGES = {
  usedOnce: `\`i18n.{{key}}\` is used once. Put the translation call where it is used, for example as \`s__('Context|Text')\` in the template. See ${DOCS_URL}.`,
  unused: `\`i18n.{{key}}\` is not read in this component. Remove it, unless another module reads it as \`Component.i18n.{{key}}\`. See ${DOCS_URL}.`,
  removeKey: 'Remove `i18n.{{key}}`.',
};

const INLINABLE_CALLEES = new Set(['__', 's__', 'n__', 'sprintf']);
// `sprintf` is left out: its arguments usually reference script scope.
const FIXABLE_CALLEES = new Set(['__', 's__', 'n__']);

// Other values (`sanitize(...)`, arrays, objects) are allowed by the docs even when read once.
const isInlinable = (value) =>
  value?.type === 'CallExpression' && INLINABLE_CALLEES.has(value.callee.name);

const isFixable = (value) =>
  FIXABLE_CALLEES.has(value.callee.name) && value.arguments.every((arg) => arg.type === 'Literal');

// The quote of the directive attribute a template read sits in, if any.
const enclosingQuote = (sourceCode, node) => {
  let current = node;
  while (current && current.type !== 'VExpressionContainer') current = current.parent;
  if (current?.parent?.type !== 'VAttribute') return null;
  const char = sourceCode.text[current.range[0]];
  return char === '"' || char === "'" ? char : null;
};

const isMemberAccess = (parent, node) =>
  parent?.type === 'MemberExpression' && parent.object === node && !parent.computed;

/**
 * Flags keys of a literal `i18n: { ... }` option that the component never reads (remove it), or
 * reads once when the value is a plain translation call (inline it). Keys read twice or more may
 * stay since that's a valid reuse of our translations.
 *
 * Walks the script and template ASTs and classifies each `$options.i18n.<key>` read:
 * - Plain read (`$options.i18n.title`): counted.
 * - Indexed or called (`$options.i18n.labels[status]`, `$options.i18n.count(n)`): exempt, since
 *   lookup maps and plural functions cannot be inlined.
 * - Anything else (destructuring, passing `$options.i18n` whole, `$options.i18n[key]`): the
 *   file is skipped since it's not reliable.
 *
 * Reports once both ASTs are walked. A single-use key is auto-fixed when its value is a
 * `__`/`s__`/`n__` call with literal arguments. Unread keys only get a suggestion, since another
 * module may read them as `Component.i18n.<key>`.
 */
export const vueNoSingleUseI18nKeys = {
  meta: {
    type: 'suggestion',
    docs: {
      description: 'Disallow `i18n` option keys that a Vue component reads at most once',
    },
    fixable: 'code',
    hasSuggestions: true,
    schema: [],
    messages: MESSAGES,
  },
  create(context) {
    const { sourceCode } = context;
    const reads = new Map();
    const exempt = new Set();
    let uncountable = false;
    let i18nOption = null;
    let i18nObject = null;

    // Removes a property with one adjacent comma, keeping a trailing comma on the new last one.
    const removeProperty = (fixer, property) => {
      const before = sourceCode.getTokenBefore(property);
      const after = sourceCode.getTokenAfter(property);
      if (before.value === ',') return fixer.removeRange([before.range[0], property.range[1]]);
      if (after.value === ',') {
        return fixer.removeRange([property.range[0], sourceCode.getTokenAfter(after).range[0]]);
      }
      return fixer.removeRange([before.range[1], after.range[0]]);
    };

    const removeKey = (fixer, property) =>
      removeProperty(fixer, i18nObject.properties.length === 1 ? i18nOption : property);

    const inlineFix = (property, read) => {
      if (!isFixable(property.value)) return null;
      const text = sourceCode.getText(property.value);
      const quote = enclosingQuote(sourceCode, read);
      if (quote && text.includes(quote)) return null;
      return (fixer) => [fixer.replaceText(read, text), removeKey(fixer, property)];
    };

    const onOptions = (node) => {
      const { parent } = node;
      // `this.$options` is visited as the member expression, not its property identifier.
      if (parent?.type === 'MemberExpression' && parent.property === node) return;
      if (!isMemberAccess(parent, node)) {
        uncountable = true;
        return;
      }
      if (parent.property.name !== I18N_OPTION) return;

      const read = parent.parent;
      if (!isMemberAccess(read, parent)) {
        uncountable = true;
        return;
      }
      const key = read.property.name;
      const user = read.parent;
      if (
        (user?.type === 'MemberExpression' && user.object === read) ||
        (user?.type === 'CallExpression' && user.callee === read)
      ) {
        exempt.add(key);
      } else {
        reads.set(key, [...(reads.get(key) ?? []), read]);
      }
    };

    const finalize = () => {
      if (!i18nObject || uncountable) return;
      for (const property of i18nObject.properties) {
        const key = property.type === 'Property' && getPropertyKeyName(property);
        if (!key || exempt.has(key)) continue;
        const keyReads = reads.get(key) ?? [];
        if (keyReads.length === 0) {
          context.report({
            node: property,
            messageId: 'unused',
            data: { key },
            suggest: [
              { messageId: 'removeKey', data: { key }, fix: (fixer) => removeKey(fixer, property) },
            ],
          });
        } else if (keyReads.length === 1 && isInlinable(property.value)) {
          context.report({
            node: property,
            messageId: 'usedOnce',
            data: { key },
            fix: inlineFix(property, keyReads[0]),
          });
        }
      }
    };

    const optionsVisitor = {
      "Identifier[name='$options']": onOptions,
      "MemberExpression[property.name='$options']": onOptions,
    };

    return defineTemplateBodyVisitor(
      context,
      {
        ...optionsVisitor,
        // Template traversal runs after the script's `Program:exit`.
        "VElement[parent.type!='VElement']:exit": finalize,
      },
      {
        ...optionsVisitor,
        ExportDefaultDeclaration(node) {
          i18nOption = findOption(getComponentOptions(node), I18N_OPTION);
          const value = i18nOption?.value;
          i18nObject = value?.type === 'ObjectExpression' ? value : null;
        },
        'Program:exit': () => {
          if (!context.sourceCode.ast.templateBody) finalize();
        },
      },
    );
  },
};

import { defineTemplateBodyVisitor } from './utils/eslint_parsing_utils.mjs';
import { getPropertyKeyName } from './utils/gl_slots_mixin_injection.mjs';
import { findOption, getComponentOptions, toKebabCase } from './utils/component_options.mjs';

export const MESSAGE_IDS = {
  unused: 'unused',
};

const camelize = (name) => name.replace(/-(\w)/g, (_, char) => char.toUpperCase());
const capitalize = (name) => name.charAt(0).toUpperCase() + name.slice(1);

// The keys Vue's `resolveDirective` tries for `v-<name>`, in order.
const candidateKeys = (templateName) => {
  const camel = camelize(templateName);
  return [templateName, camel, capitalize(camel)];
};

/**
 * Disallow registering directives in a component's `directives` option that
 * its `<template>` never uses, the directive counterpart of
 * `vue/no-unused-components`. `vue/no-undef-directives` covers the reverse.
 *
 * Components without a `<template>` (render functions, `template:` strings),
 * a non-literal `directives` value and computed keys are skipped, since their
 * usage cannot be read statically.
 */
export const vueNoUnusedDirectives = {
  meta: {
    type: 'suggestion',
    docs: {
      description: 'disallow registering directives that are not used inside templates',
    },
    schema: [],
    messages: {
      [MESSAGE_IDS.unused]:
        "Directive '{{key}}' is registered but 'v-{{templateName}}' is not used in the template. Remove the registration.",
    },
  },
  create(context) {
    const used = new Set();
    let directivesObject = null;

    const finalize = () => {
      if (!directivesObject) {
        return;
      }
      const usedKeys = new Set([...used].flatMap(candidateKeys));
      directivesObject.properties.forEach((property) => {
        if (property.type !== 'Property' || property.computed) {
          return;
        }
        const key = getPropertyKeyName(property);
        if (key && !usedKeys.has(key)) {
          context.report({
            node: property,
            messageId: MESSAGE_IDS.unused,
            data: { key, templateName: toKebabCase(key) },
          });
        }
      });
    };

    return defineTemplateBodyVisitor(
      context,
      {
        'VAttribute[directive=true]': (node) => {
          const { name } = node.key;
          if (name.type === 'VIdentifier') {
            used.add(name.rawName);
          }
        },
        // Template traversal runs after the script's `Program:exit`.
        "VElement[parent.type!='VElement']:exit": finalize,
      },
      {
        ExportDefaultDeclaration: (node) => {
          const value = findOption(getComponentOptions(node), 'directives')?.value;
          directivesObject = value?.type === 'ObjectExpression' ? value : null;
        },
      },
    );
  },
};

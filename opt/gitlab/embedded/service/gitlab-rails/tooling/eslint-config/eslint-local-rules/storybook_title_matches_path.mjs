import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
// Anchored at the repository root, so a checkout directory named `ee` or `jh` isn't read as one.
const STORY_PATH_PATTERN = /^((?:ee|jh)\/)?app\/assets\/javascripts\/(.+)\.stories\.js$/;

export const expectedStoryTitle = (filename) => {
  const match = path.relative(ROOT, filename).replaceAll('\\', '/').match(STORY_PATH_PATTERN);

  return match ? `${match[1] ?? ''}${match[2]}` : null;
};

const findMetaObject = (program, declaration) => {
  if (declaration.type === 'ObjectExpression') return declaration;
  if (declaration.type !== 'Identifier') return null;

  const declarator = program.body
    .map((node) => (node.type === 'ExportNamedDeclaration' ? node.declaration : node))
    .filter((node) => node?.type === 'VariableDeclaration')
    .flatMap((node) => node.declarations)
    .find(({ id }) => id.type === 'Identifier' && id.name === declaration.name);

  return declarator?.init?.type === 'ObjectExpression' ? declarator.init : null;
};

const staticString = (node) => {
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
  if (node.type === 'TemplateLiteral' && !node.expressions.length)
    return node.quasis[0].value.cooked;
  return null;
};

// Titles are spelled out, not left to Storybook's autotitle, which drops a filename that
// repeats its directory (`data_table/data_table`) and so changes story IDs.
export const storybookTitleMatchesPath = {
  meta: {
    type: 'suggestion',
    docs: {
      description: 'require a Storybook story title to match its file path',
    },
    fixable: 'code',
    schema: [],
    messages: {
      missingTitle: "Add `title: '{{expected}}'`, the story's file path.",
      mismatch: "Story title must match its file path: '{{expected}}'.",
    },
  },
  create(context) {
    const expected = expectedStoryTitle(context.physicalFilename ?? context.filename);
    if (!expected) return {};

    return {
      ExportDefaultDeclaration(node) {
        const meta = findMetaObject(node.parent, node.declaration);
        if (!meta) return;

        const titleProperty = meta.properties.find(
          (property) =>
            property.type === 'Property' &&
            !property.computed &&
            (property.key.name ?? property.key.value) === 'title',
        );

        if (!titleProperty) {
          context.report({ node: meta, messageId: 'missingTitle', data: { expected } });
          return;
        }

        const { value } = titleProperty;
        const title = staticString(value);
        if (title === expected) return;

        context.report({
          node: value,
          messageId: 'mismatch',
          data: { expected },
          fix: title === null ? null : (fixer) => fixer.replaceText(value, `'${expected}'`),
        });
      },
    };
  },
};

// `no-unused-vars` cannot catch this: the parameter is read, by its own spread.
// Proving it dead needs call-site analysis. See gitlab-org/gitlab#631447.

const EXPORT_TYPES = new Set(['ExportNamedDeclaration', 'ExportDefaultDeclaration']);

function isEmptyObject(node) {
  return node?.type === 'ObjectExpression' && node.properties.length === 0;
}

// Null for a computed key, whose name is unknown until run time.
function getStaticKeyName(prop) {
  if (prop.key.type === 'Literal' && typeof prop.key.value === 'string') {
    return prop.key.value;
  }
  if (!prop.computed && prop.key.type === 'Identifier') {
    return prop.key.name;
  }
  return null;
}

function getObjectPattern(fn) {
  if (fn.params.length !== 1) return null;

  const [param] = fn.params;
  if (param.type === 'ObjectPattern') return param;
  if (
    param.type === 'AssignmentPattern' &&
    param.left.type === 'ObjectPattern' &&
    isEmptyObject(param.right)
  ) {
    return param.left;
  }
  return null;
}

export const noUnsuppliedFactoryParam = {
  meta: {
    type: 'suggestion',
    docs: {
      description:
        'Disallow a factory parameter that defaults to `{}`, is only read by its own spread, and that no call site supplies',
      recommended: true,
    },
    messages: {
      unsuppliedFactoryParam:
        'The `{{ name }}` parameter of `{{ factory }}` defaults to `{}` and is only read by its own spread, ' +
        'and no call in this file supplies it. Spreading `{}` adds no keys, so the parameter and its spread ' +
        'have no effect. Remove both. See gitlab-org/gitlab#631447.',
    },
    schema: [],
  },
  create(context) {
    const { sourceCode } = context;
    const candidates = [];

    function findSpreadOnlyParams(fn, pattern) {
      const declared = sourceCode.getDeclaredVariables(fn);

      return pattern.properties.flatMap((prop) => {
        if (prop.type !== 'Property') return [];
        if (prop.value.type !== 'AssignmentPattern') return [];
        if (!isEmptyObject(prop.value.right)) return [];
        if (prop.value.left.type !== 'Identifier') return [];

        const keyName = getStaticKeyName(prop);
        if (keyName === null) return [];

        const variable = declared.find((v) => v.name === prop.value.left.name);
        if (!variable) return [];

        // A write beyond the default makes the value unprovable.
        if (variable.references.some((r) => r.isWrite() && r.identifier !== prop.value.left)) {
          return [];
        }

        const reads = variable.references.filter((r) => r.isRead());
        if (reads.length !== 1) return [];

        const { identifier } = reads[0];
        if (
          identifier.parent?.type !== 'SpreadElement' ||
          identifier.parent.parent?.type !== 'ObjectExpression'
        ) {
          return [];
        }

        return [{ prop, keyName }];
      });
    }

    // Null when the factory has no binding, or is exported and so may be called elsewhere.
    function getFactoryVariable(fn) {
      if (fn.type === 'FunctionDeclaration') {
        if (!fn.id || EXPORT_TYPES.has(fn.parent?.type)) return null;
        return sourceCode.getDeclaredVariables(fn).find((v) => v.name === fn.id.name);
      }

      const declarator = fn.parent;
      if (
        declarator?.type !== 'VariableDeclarator' ||
        declarator.init !== fn ||
        declarator.id.type !== 'Identifier' ||
        EXPORT_TYPES.has(declarator.parent?.parent?.type)
      ) {
        return null;
      }
      return sourceCode.getDeclaredVariables(declarator).find((v) => v.name === declarator.id.name);
    }

    // Null when any call makes the key set unknowable.
    function collectSuppliedKeys(variable) {
      const supplied = new Set();
      let callCount = 0;

      for (const ref of variable.references) {
        if (ref.isWrite()) {
          if (ref.init) continue;
          return null;
        }

        const { parent } = ref.identifier;
        if (parent?.type !== 'CallExpression' || parent.callee !== ref.identifier) {
          return null;
        }
        callCount += 1;

        const [arg] = parent.arguments;
        if (arg === undefined) continue;
        if (arg.type !== 'ObjectExpression') return null;

        for (const prop of arg.properties) {
          if (prop.type !== 'Property') return null;

          const name = getStaticKeyName(prop);
          if (name === null) return null;
          supplied.add(name);
        }
      }

      return callCount > 0 ? supplied : null;
    }

    function check(fn, pattern) {
      const params = findSpreadOnlyParams(fn, pattern);
      if (params.length === 0) return;

      const variable = getFactoryVariable(fn);
      if (!variable) return;

      const supplied = collectSuppliedKeys(variable);
      if (supplied === null) return;

      params
        .filter(({ keyName }) => !supplied.has(keyName))
        .forEach(({ prop, keyName }) => {
          context.report({
            node: prop,
            messageId: 'unsuppliedFactoryParam',
            data: { name: keyName, factory: variable.name },
          });
        });
    }

    function collect(node) {
      const pattern = getObjectPattern(node);
      if (pattern) candidates.push({ fn: node, pattern });
    }

    return {
      ArrowFunctionExpression: collect,
      FunctionExpression: collect,
      FunctionDeclaration: collect,
      // Deferred so every call site is parsed and every `parent` is set.
      'Program:exit': () => candidates.forEach(({ fn, pattern }) => check(fn, pattern)),
    };
  },
};

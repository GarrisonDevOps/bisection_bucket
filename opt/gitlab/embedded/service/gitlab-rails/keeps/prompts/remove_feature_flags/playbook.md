# Feature flag removal playbook

Language-specific rules for removing a feature flag from the GitLab codebase. Read the section for
each file type you touch.

## How flags are referenced

| Layer | Pattern |
| --- | --- |
| Ruby | `Feature.enabled?(:flag_name, actor)`, `Feature.disabled?(:flag_name, actor)` |
| Ruby (frontend push) | `push_frontend_feature_flag(:flag_name, actor)` |
| HAML | `- if Feature.enabled?(:flag_name, project)` |
| Vue | `this.glFeatures.flagName` via `glFeatureFlagMixin()` |
| JavaScript | `gon?.features?.flagName` |
| RSpec | `stub_feature_flags(flag_name: false)` |
| Jest | `provide: { glFeatures: { flagName: true } }` |

The Vue and JavaScript forms use the lowerCamelCase spelling of the flag name, so a repository search
for the snake_case name alone will miss them.

## Ruby

Simplify every branch as though the flag check returns the resolved value. A method whose whole body
is `Feature.enabled?(:flag_name)` should return the literal instead, and its callers should then be
simplified too. `Feature.disabled?` is the negation.

After the branches collapse, look for what became dead: private methods with no remaining callers,
constants no longer referenced, `require`s for files that are no longer used.

## RSpec

Feature flags are enabled by default in specs, so a block with no `stub_feature_flags` call is
testing the enabled path.

- Remove `context` blocks that stub the flag to the value that is going away, including the whole
  block, not just the stub.
- Remove `stub_feature_flags` calls that set the flag to the value that is being kept — they are now
  redundant.
- Update `describe` and `context` descriptions that name the flag.
- If a spec file existed only to test flag behavior, delete the file.

## HAML

Collapse the conditional and keep the surviving branch.

When you delete a `render` call, follow it: check whether the partial is rendered anywhere else, and
delete the partial file if it is not. Watch for `render 'path'`, `render partial: 'path'`, and
`render layout: 'path'`. Leave dynamic paths (`render partial_path`) alone — you cannot resolve them
statically.

## Vue

Remove the `glFeatures.flagName` references and collapse `v-if`/`v-else`, conditional classes, and
ternaries in props.

Then handle the mixin, carefully:

- Search the whole file for any other `glFeatures.` reference.
- If any remain, leave `glFeatureFlagMixin()` and its import completely untouched.
- Only if none remain, remove both the import and the mixin registration.

Never rewrite the syntax of other flags, never add optional chaining to `glFeatures`, and never
modify a flag other than the one being removed.

If a component becomes unreachable because its only render site was behind the flag, delete the
component and its spec.

## JavaScript

Collapse `if (gon?.features?.flagName)` branches. Remove destructuring such as
`const { flagName } = gon.features ?? {};` when nothing else uses it. Replace ternaries and object
properties with the resolved value.

Then remove what is now unused: imports, exported functions with no importers, and modules that are
no longer imported anywhere.

## Jest

Same shape as RSpec. Remove tests for the path that is going away, drop `glFeatures` entries from
`provide` blocks and `jest.mock` factories, and update descriptions that name the flag. Delete the
file if it only ever tested the flag.

## Markdown documentation

Do not remove existing history notes that mention the flag. Add one new note in the form the goal
gives you, then remove every other mention of the flag.

Collapse consecutive blank lines to a single blank line before you finish — markdownlint fails
otherwise.

Skip `doc-locale/`, changelog files, and `graphql/reference/`. These are generated or
translated.

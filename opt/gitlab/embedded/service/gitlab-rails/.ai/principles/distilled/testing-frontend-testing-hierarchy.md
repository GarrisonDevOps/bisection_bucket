---
source_checksum: db0151cd446382db
distilled_at_sha: b0b7e1628f9fb689a18cee2ec91c621c6a26dd2d
---
<!-- Auto-generated from docs.gitlab.com by gitlab-ai-principles-distiller — do not edit manually -->

# Frontend Testing Hierarchy Principles

## Checklist

### Test Type Decision

- Choose the test type for each behavior, not for each file; start at the lowest level that can prove the behavior (unit/component, then frontend integration, then Capybara), and expect a merge request to need more than one type.
- Use an end-to-end test in `qa/qa/specs/` for a golden user journey that requires a fully running GitLab instance.
- DO NOT use a unit or component test to prove an interaction between components, because child-component mocks cannot prove that interaction. DO NOT use a frontend integration test when a unit or component test can prove the behavior.
- Use a unit or component test for behavior that depends on polling or another timer interval (fake timers let the test advance time); DO NOT use a frontend integration test for it (it uses real timers, so the test must wait the full interval).
- Use a frontend integration test for UI that depends on a permission level (for example, a hidden button or read-only view); record a fixture variant as a user with that permission level.
- DO NOT write a Capybara feature spec that needs only an authenticated user and factory records; fixtures supply both.

### Existing Capybara Specs

To find Capybara feature specs that can move to frontend integration tests,
run `tooling/bin/fe_test_janitor <spec_file_or_directory>`. Its labels are
suggestions. Check each label against
[Find tests to move](https://docs.gitlab.com/development/testing_guide/frontend_testing/#find-tests-to-move)
before you move a test.

### How to Write Each Test Type

See `.ai/principles/distilled/testing-jest.md` for the full how-to on all three
layers: unit/component tests, frontend integration tests, and Capybara feature
tests.

For frontend integration setup, handlers, fixtures, and request counting, see
[Frontend integration tests](https://docs.gitlab.com/development/testing_guide/frontend_testing/#frontend-integration-tests).

### Unit Tests

- Write unit tests for exported functions, classes, Vuex actions, and complex Vuex mutations; DO NOT write unit tests for non-exported functions, constants, or Vue computed properties/methods (they are implementation details covered implicitly by component tests).
- DO NOT test library internals (for example, Vue computed properties that merely delegate to a library); test the rendered template output instead.
- DO NOT assert on `wrapper.vm` properties — test the rendered template to reflect how a user perceives the component.
- Mock all server requests, other exported classes, and asynchronous background operations in unit tests; DO NOT mock non-exported functions, methods of the class under test, or pure utility functions.
- DO NOT load full HTML pages in unit tests — create single DOM elements when the test only operates on them.

### Component Tests

- Use component tests for individual Vue components only; DO NOT use them for full Vue applications (use frontend integration tests instead) or HAML templates (which contain no frontend logic).
- Mock side effects (network requests) and child components in component tests; DO NOT mock methods or computed properties of the component under test, and DO NOT mock Vuex — set Vuex state via mutations and mock only side effects.

### Integration Tests (Frontend)

- Use frontend integration tests for page bundles (`index.js` files in `app/assets/javascripts/pages/`) and Vue applications outside page bundles.
- Use HAML fixtures (not rendered HAML) in integration tests; mock all server requests and non-perceivable background operations.
- DO NOT mock the DOM, component properties/state, or Vuex stores in integration tests — test on the real DOM and let the full component tree interact.

### Feature Tests (Frontend)

- Use a frontend integration test (`ee/spec/frontend/integration/`, EE-only) when the test covers multi-component interaction on a single page and backend responses can be represented with fixtures, including recorded unlicensed payloads. Use a Capybara feature test (`spec/features/`) when the test requires database state, authorization, server-side validations, real-time updates, backend license enforcement, cross-page navigation, backend state not representable with fixtures, multiple Vue applications on the same page, an accessibility scan with `be_axe_clean`, drag and drop, file upload, or session/cookie state.
- Add `:js` metadata to RSpec feature specs that require JavaScript; DO NOT omit it when the test depends on JavaScript execution.
- Before asserting on backend attributes in a Capybara spec, assert on a visible page element first to confirm the operation completed; DO NOT use `wait_for_requests` as a substitute (race conditions can occur).
- When moving a Capybara spec that checks the database after a UI action (for example, `.reload` or `Model.count`), keep it in Capybara if the database change is the point of the test; if the check only stands in for what the user sees, assert the UI result instead, then move it to a frontend integration test. The Capybara criteria above still take precedence.

### Test File Placement

- Place Jest unit and component tests in `spec/frontend/`; place frontend integration tests in `ee/spec/frontend/integration/` (EE-only — adding any file under `spec/frontend/integration/` fails ESLint); place Capybara feature tests in `spec/features/`.
- Place EE-specific tests under the `ee/spec` folder following the same structure.

## Authoritative sources

For the full picture, see:

- doc/development/testing_guide/frontend_testing.md
- doc/development/testing_guide/testing_levels.md


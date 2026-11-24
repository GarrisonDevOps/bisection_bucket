# Frontend Testing Hierarchy — Which Test to Write

> **Prerequisite:** Read `.ai/principles/distilled/testing-jest.md` first — it
> is the authoritative reference for *how* to write every test type covered
> here (unit, frontend integration, Capybara, fixtures).

This baseline answers only one question: **which kind of test to write**.

---

## Checklist

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

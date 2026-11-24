---
stage: Security Platform
group: Secrets Manager Application
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Secrets Manager frontend development
ignore_in_report: true
---

The Secrets Manager frontend decides what to show. The backend decides what is true.
Most frontend bugs came from the frontend deriving a fact that the backend already knew: who can act, which state the secrets manager is in, or whether a dependency is reachable.
When you add or change a control, start by asking which backend fact it should read, not which conditions it should compute.

Reviewers rely on this page, and so does the automated reviewer that uses the Secrets Manager principle.
If you make a significant change to the secrets manager frontend, update this page to reflect the current behavior. A follow-up merge request is fine.

## Language and the user's mental model

The code and the user describe the same feature in different words. Copy should use the user's mental model.

Capitalize **GitLab Secrets Manager** when you name the product.
Write **secrets manager** in lowercase when you mean a specific example of the feature itself, for example "the group's secrets manager is provisioning".

Users *enable* or *disable* GitLab Secrets Manager. They do not provision, enroll, or opt in. These actions happen under
the hood, but they are the developers' concerns, not the users'. `provisioning` and `enrollment` appear in user-facing
strings only in a few error messages that name a failed system action.
New copy should say **Enable GitLab Secrets Manager** and describe the result, not the mechanism.

The **beta cohort** is the set of groups that opted in during the free beta program, before the feature was paid.
They keep read access to the secrets they created after the beta ended, until they start a trial or enable the add-on.
Copy and behavior for them should treat the beta as over, not as a grace period.

Who to contact depends on what they need to do:

- Enabling or disabling the feature or starting a trial is for the **group owner** or **instance administrator**, because either can do it depending on the realm.
- Granting secrets permissions is for the **group owner** or **project owner** of that scope, because grants live in that scope's permissions table and an instance administrator does not manage them.
- Billing actions, such as accepting on-demand billing or buying credits, are for the **subscription owner** or **billing administrator**. This role is often given to a different person from the group owner.

Each term is correct in its own context. Do not unify them.

A denial should name its cause and who can help.
"Contact your group owner or instance administrator to enable GitLab Secrets Manager" is a denial the user can act on. "Try again later" and "The resource does not exist" are not.

Use strings inline in the template unless the string is reused.
Strings that several components share, such as the blocked-reason alerts, live in `constants.js`.

## Where the frontend lives

The secrets page is a Vue application with Vue Router and Apollo at `ee/app/assets/javascripts/ci/secrets/`.
`index.js` mounts `components/secrets_app.vue`, which owns the shared state and provides it to the feature components.

- `components/secrets_table/`, `components/secret_form/`, and `components/secret_details/` hold the feature components.
- `graphql/queries/`, `graphql/mutations/`, and `graphql/fragments/` hold the GraphQL documents, colocated with the app.
- `router.js` defines the routes. `constants.js` holds shared constants and copy.
- `context_config.js` holds everything that differs between a group and a project.

The secrets manager also renders outside this tree:

- The settings block for groups and projects at `ee/app/assets/javascripts/pages/projects/shared/permissions/secrets_manager/`, with its own `context_config.js`. It holds the enrollment toggle, the trial and add-on actions, and the permissions table.
- The instance settings card for GitLab Self-Managed at `ee/app/assets/javascripts/admin/application_settings/general/secrets_manager_instance_enrollment/`.
- Calls to action on other pages, for example the vulnerability details sidebar at `ee/app/assets/javascripts/vulnerabilities/components/vulnerability_details/sidebar/`. These read a small payload of booleans and paths from a Rails helper and derive their variant in the component.

These surfaces follow the same rules as the secrets page. A change to how a state or ability is derived usually needs to be checked against all of them.

Depending on which files a change touches, these sections have more detail:

| Changed files | Section |
|---------------|---------|
| `ee/app/helpers/secrets_helper.rb` | [Where the frontend gets its facts](#where-the-frontend-gets-its-facts) and [Calls to action on other pages](#calls-to-action-on-other-pages) |
| `context_config.js` in either tree, or a change for only one of group and project | [One application for groups and projects](#one-application-for-groups-and-projects) |
| `secrets_app.vue`, or any `inject` of an ability or state | [Gating controls](#gating-controls) and [States and what the user sees](#states-and-what-the-user-sees) |
| A `v-if`, `:disabled`, or `skip()` that reads an ability, a status, or `isOpenbaoHealthy` | [Gating controls](#gating-controls) and [Dependencies the frontend must survive](#dependencies-the-frontend-must-survive) |
| An alert, popover, or polling query | [States and what the user sees](#states-and-what-the-user-sees) |
| User-facing strings, in a template or in `constants.js` | [Language and the user's mental model](#language-and-the-users-mental-model) |
| `mock_data.js` or a spec under `ee/spec/frontend/ci/secrets/` | [Frontend tests](#frontend-tests) |
| A feature flag check | [Feature flags that change the frontend](#feature-flags-that-change-the-frontend) |

### One application for groups and projects

Group secrets and project secrets share one codebase.
The differences between the two contexts are small enough that one application serves both: which GraphQL documents to send, which paths to link to, and a few entity-specific fields, such as the group-only **Protected branches** option and the project-only **Branches** field on the secret form.

`SECRETS_MANAGER_CONTEXT_CONFIG` in `context_config.js` holds the document and path variance: the queries and mutations for each operation, the `lookup` functions that pull the context-specific field out of a response, and the page size for the list.
The settings block has its own configuration with the same shape.
Field differences are handled where the fields render, with a check on `contextConfig.type`.

Components receive the configuration through `contextConfig` and read `contextConfig.getStatus.query`, `contextConfig.createSecret.mutation`, and so on.
They should not branch on `contextConfig.type` for anything the configuration can express.

When you add a difference in documents or paths, add it to the context configuration rather than to a component.
When you add a feature, design it for both contexts even if you implement one first, and avoid shapes that only fit one of them.
The backend follows the same parity rule between `ProjectSecretsManager` and `GroupSecretsManager`, and reviewers check for it on both sides.
The structure of the shared application is scheduled for refinement; see [Known technical debt](#known-technical-debt).

### Calls to action on other pages

The secrets manager also appears on pages it does not own, as a card or banner that points users at it.
The vulnerability details sidebar shows one for secret-detection findings, and the CI/CD variable drawer shows one for masked variables.
These surfaces share one contract, and a new one should follow it.

- A Rails helper in `ee/app/helpers/secrets_helper.rb` builds a small payload of facts: whether the user can open the secrets page, whether they can start a trial, and the paths for each. The helper checks the destination page's ability, not availability, so a link never leads to a page the user cannot open.
- An empty payload hides the card. The helper returns nothing when the feature is not offered at all, for example an unlicensed group or a personal namespace, because there is nobody the user could ask.
- The component derives the variant from the facts: **View** when the user can open the page, **Try** when they can start a trial, and otherwise **Request**, which opens a modal naming who to ask. The payload never carries a variant name.
- Each surface has its own feature flag, so a card can roll out on its own and be turned off without touching the secrets page.
- Links out of a form open in a new tab, so an unsaved form is not lost.

The host page owns the component's placement and events. The payload and the variant rules belong to the secrets manager.
When you add a surface, add its helper method next to the existing ones and reuse the variant mapping rather than writing a new one.

## Where the frontend gets its facts

The frontend reads three kinds of fact, from three places.

| Fact | Source | Reaches the frontend as |
|------|--------|------------------------|
| Can the user start a trial, enable the add-on, provision, or enroll? | Rails policies, evaluated in `ee/app/helpers/secrets_helper.rb` | Booleans in the mount element's data attributes, for example `canProvision` and `canStartTrial`. Available before the secrets manager exists. |
| Can the user read, create, update, or delete secrets? | OpenBao capabilities, resolved by the backend for the current user | `userPermissions` on the secrets manager status query. `null` until the secrets manager is active. |
| Which state is the secrets manager in, and does the entitlement allow writes? | `status`, `readOnly`, and `writeDenialReason` on the status query; the entitlement query for the top-level group | Provided from `secrets_app.vue` as `secretManagerStatus`, `isReadOnly`, and `entitlement`. |

Two rules follow from this split.

The backend sends facts, the frontend chooses presentation.
A payload carries booleans and paths like `canStartTrial` and `startTrialPath`, not a variant name like `showTryButton`.
The component maps facts to a variant. That keeps copy and layout changes inside the frontend, where they do not need a backend review, and keeps the backend from encoding a design decision.

Abilities that exist before provisioning come from app data. Abilities that depend on the secrets manager come from the status query.
The **New secret** button is the clearest example: unprovisioned, it fires the provisioning mutation and reads `canProvision` from app data; provisioned, it opens the secret form and reads `userPermissions.createSecrets`.
Do not reuse one for the other.

## Environments the frontend must account for

The same component serves several environments, and they do not reach the same states.
A change that looks complete on GitLab.com can be unreachable, or worded wrongly, on an offline environment.

The entitlement is scoped to the top-level group on GitLab.com and to the whole instance on GitLab Self-Managed.
A subgroup or project reads its root ancestor's entitlement, never its own.

`offlineLicense` on the entitlement decides most of the rest. It is computed in GraphQL as the inverse of an online cloud license, and is null on GitLab.com. It is not a value the entitlement resolver returns.

| Environment | Where the entitlement comes from | What the frontend can show |
|---|---|---|
| GitLab.com | CustomersDot, per top-level group | Every state, including all blocked reasons. Trials and add-on purchases are available. |
| GitLab Self-Managed, online cloud license | CustomersDot, instance-wide | The same states as GitLab.com. |
| GitLab Self-Managed, offline environment with Flex | Local add-on records | `offline_paid` or blocked. No trial, because trials need CustomersDot. Flex consumes GitLab Credits, so credit copy applies. |
| GitLab Self-Managed, offline environment without Flex | Local add-on records | `offline_paid` or blocked. No trial, and no credit copy, because the feature is bundled rather than metered. |

Two consequences for copy and gating:

- Remedies differ. Telling an administrator in an offline environment to visit the Customers Portal or buy credits is wrong; their fix is a license that includes the add-on. Check `offlineLicense` before you write a remedy.
- Surfaces differ. The instance settings card is available only on GitLab Self-Managed. The trial and add-on buttons need an online cloud license, so an offline environment shows the enrollment toggle instead.

### The settings hierarchy on GitLab.com

One component, `secrets_manager_settings.vue`, renders the settings block at three levels, and shows a different subset at each.
The switch is `isNamespaceEnrollable`, which the Rails helper sets to `namespace.root? && Gitlab.com?`.

| Level | Where it renders | What it controls |
|---|---|---|
| Top-level group | **Settings** > **Secure**, its own page | Enrollment for the whole namespace, the trial and add-on actions, and the entitlement banners. Also the permissions table. |
| Subgroup | **Settings** > **General** | The permissions table. No enrollment, no entitlement banners. |
| Project | **Settings** > **General** | The permissions table. No enrollment, no entitlement banners. |

The split follows from where the entitlement lives. Enrollment and billing actions belong to the top-level group, because that is the namespace CustomersDot answers for, so the component hides them everywhere else: `showEntitlementBanners` requires `isNamespaceEnrollable`, and the subgroup partial is guarded by `unless @group.root?` so the top-level group never renders the block twice.

Permissions are the exception, because a grant is scoped to the group or project that owns it. The permissions table therefore renders at every level, and is gated on OpenBao health rather than on enrollment.

On GitLab Self-Managed there is no such split: enrollment is instance-wide and lives on the administrator's settings card, so every group and project shows only the permissions table.

## Gating controls

A control the user can never use should not render.
A control the user cannot use right now, because something is loading or a dependency is unavailable, should render disabled with an explanation.
Reviewers most often had to correct the frontend when a control was gated on the wrong fact, or on no fact at all.
These rules cover the cases that came up.

### Fail closed on a missing fact

When an ability or a state is `null` or `undefined`, treat it as denied.
A missing `userPermissions` means the secrets manager is not active yet. A missing entitlement means the backend did not answer.
Neither is permission.
Inject abilities with a default of `false`, and write the spec for the missing case, not only for `true` and `false`.

### Gate an entry point on the destination page's own check

A link or button that opens another page must use the ability that page's controller checks.
`SecretsManagement::Availability` answers whether the feature is licensed and enrolled. It does not know the entitlement state or the user's role, so it is not enough on its own.
The secrets page checks the Rails ability `read_project_secrets` or `read_secret`, so a call to action that links to it reads the same ability.
The page does not check the user's OpenBao grant: a user with the ability but no grant reaches the page and sees an empty state that explains the gap, so the entry point does not need to know about grants either.

**Case study:** the vulnerability page's secrets manager card once gated its **View** button on availability.
For an enrolled group whose entitlement was still `trial_eligible`, availability was true, but the project page returned 404 because the policy hides projects in that state.
The button linked to a page the user could not open. Reading the controller's ability fixed it for that case and for two others nobody had reported.
See [merge request 261826](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261826).

### Hide, do not explain, with one exception

When the user lacks the ability to act, hide the control.
Do not render a disabled button with a tooltip, and do not replace the button's text with an explanation.
The exception is the request pattern: when a user cannot use or try the feature but someone in their group could enable it, show a **Request** button that opens a modal naming who to ask.
That is the only sanctioned way to show a control for an ability the user does not have.
A disabled control is still right for a transient state, such as a mutation in flight or OpenBao being unreachable.

### Keep the gating boolean honest about blocked and read-only states

`userPermissions` already accounts for the entitlement and strict read-only mode, so `createSecrets` is false while the top-level group is blocked.
What it does not account for is an archived or pending-deletion namespace. `secrets_app.vue` ANDs that in as `isEntityBlocked`.
If you add a new axis that blocks writes, add it in `secrets_app.vue` where the others are composed, not in the component that renders the button.

## States and what the user sees

The secrets manager, the entitlement, and the user's grants are independent states, and most bugs come from a combination the code did not handle.
For the states themselves and the backend's required side effects, see [Secrets Manager states and side effects](states_and_side_effects.md).
This section covers the frontend's half.

### Entitlement and blocked reasons

`constants.js` mirrors the backend's entitlement states and blocked reasons, and `TRIAL_ALERT_OPTIONS_BLOCKED` maps each blocked reason to its alert.
A `BLOCKED` entitlement still permits reads, so the page renders, read-only, with the alert that names the reason.
Only `INELIGIBLE` denies reads. That state also covers a failed CustomersDot lookup, because the backend fails closed, so copy for `INELIGIBLE` must not promise a trial.

Beta-cohort groups keep read access after the beta program ends. `isBetaUser` reads `entitlement.betaWindowEligible`, which the backend sets only for enrolled beta groups in `trial_eligible` or `ineligible`.
Do not derive beta behavior from enrollment or dates on the frontend.

### A role without a grant

A user can hold the role the page requires and still have no OpenBao grant, because grants are managed separately in the permissions table.
When the secrets manager is active and `userPermissions.readMetadata` is false, `secrets_app.vue` skips the secrets queries and shows the empty state with an alert that asks the user to contact the group or project owner for permissions.

The alert waits for the OpenBao health check to succeed before it renders.
The capabilities lookup also returns all-false when OpenBao is down, and in that case the unhealthy warning is the right message, not a permissions message.
This is the pattern for every all-false or `null` answer: decide whether it means "denied" or "no answer" before you choose the copy.

### Asynchronous processes must stay visible

Provisioning is a queued job. It can take seconds, or it can wait behind a database health check for half an hour.
Deprovisioning, the trial chain, and the add-on chain are also asynchronous.

While a process runs, the page should show that it is running, and that state should survive a page refresh.
The **New secret** button stays mounted, in a loading state with its explanatory popover, for as long as the status is `PROVISIONING`, even though `userPermissions.createSecrets` is false until the manager is active.
Hiding the button during provisioning left the page with no signal at all.

When a process finishes and the outcome changes what the user can do, say so.
A user who watched provisioning finish but holds no create grant sees an alert that setup worked and names who can grant access.
Only users who can create secrets are taken to the secret form when provisioning completes.
Everyone else stays on the list, because a page the user is moved to must be one they can use.

Polling for a status change should stop on a terminal state and on error.
Both polling sites, in `secrets_app.vue` and in the settings block, do this.

### One alert slot per concern

A page composes several alert sources: entitlement alerts, the beta transition alert, transient success and error alerts, and dependency warnings.
Each state gets one alert, and a transient alert stacks above a persistent one.
When you add an alert, check what else renders in the same state. Two alerts saying different things about one situation is a bug reviewers catch late.

## Dependencies the frontend must survive

The frontend depends on three services through the backend: PostgreSQL, OpenBao, and CustomersDot.
Any of them can be slow or down while the page is open.

Each one backs a different part of the page, which is what decides how far an outage spreads:

- PostgreSQL backs the secrets manager status and the enrollment records.
- OpenBao backs the secrets themselves and the per-user capabilities.
- CustomersDot backs the entitlement, and nothing else.

Keep that boundary in mind when you write a denial. A CustomersDot outage must never read as "you have no secrets" or hide secrets the user can still view, because CustomersDot has no part in whether a secret exists or who may read it.

- When OpenBao is down, capabilities resolve to all-false, which looks the same as a user with no grant. `openbaoHealth` on the GraphQL API reports reachability, and `secrets_app.vue` provides it as `isOpenbaoHealthy`. Check it before you show a permissions message, as the no-read-grant alert does. Controls that write to OpenBao should disable and explain when it is false, not hide, because the user did nothing wrong. The settings block and the secrets table already follow this.
- When CustomersDot is down, the resolver replays the last-known-good entitlement for up to 24 hours if that answer allowed reads; otherwise the entitlement fails closed to `INELIGIBLE` and the page becomes read-only or hidden with no dedicated message. The refresh entitlement mutation never replays, so a user who clicks refresh during an outage sees an error even when the page still renders. Prefer copy that is still true in both cases. See [Caching and outages](fulfillment.md#caching-and-outages).
- When a query that polls returns an error, the polling stops. An error alert should be reported to Sentry once, not once per poll.

A dependency that is slow fails differently from one that is down, and usually costs more.
A control that blocks a render on an external call holds a server worker for as long as the call is allowed to take, so prefer a signal the page can render without, and make sure the wait is bounded.

The frontend should not add load to a dependency that is already struggling.
Polling should stop on a terminal state, back off rather than repeat at a fixed interval, and pause while the tab is hidden.
A page left open on a slow dependency otherwise multiplies the problem at the worst moment.

Recovery matters as much as failure.
When a dependency returns, the page should correct itself without a reload, and any message that said it was unavailable should clear.
Expect a short lag: answers about availability are cached for seconds, so a page can still show the unavailable state briefly after recovery.

When you add a control that depends on one of these, decide what it does when the dependency is unavailable, when it is slow, and when it recovers, and write that spec.

## Frontend tests

Specs live at `ee/spec/frontend/ci/secrets/`, mirroring the source layout.
Run them with this command:

```shell
yarn jest ee/spec/frontend/ci/secrets/
```

The specs mock the GraphQL layer with `createMockApollo`, so they do not need OpenBao, a license, or enrollment.
You can run the whole suite against a plain GitLab Development Kit (GDK).
Shared fixtures are in `ee/spec/frontend/ci/secrets/mock_data.js`.

Review feedback on specs repeats a few lessons:

- A spec for a gating rule should cover `true`, `false`, and missing. The missing case is the one that regresses.
- A regression spec should fail if the fix is reverted. Stubbing a call that the fixed code no longer makes proves nothing.
- Mock data should match the query. The responses in `mock_data.js` carry `__typename` on every object because the queries use fragments, and Apollo drops a response that does not match the document. A missing field in a mock shows up as a component that silently renders nothing.
- When a component watches a provided value, provide a `computed()` wrapping a `ref()` in the spec so the watcher can see it change.
- `wrapper.findByTestId()` returns a DOM wrapper. To call `.props()` or `.vm` on a component, use `wrapper.findComponentByTestId()`.
- Add the spec for both contexts, group and project, when the behavior comes from the context config.

For the general guides, see [Frontend development guidelines](../fe_guide/_index.md) and [Frontend testing guide](../testing_guide/frontend_testing.md).

## Testing in a browser

Specs cover the component logic, but the entitlement states, the provisioning flow, and the dependency failures are only visible with a running backend.
For the GDK setup, including OpenBao, see [Set up Secrets Manager locally](local_setup.md).

Entitlement comes from CustomersDot, which the GDK does not run, so exercising trial, paid, and blocked states locally needs a stub or a staging connection.
Making this easier is tracked in the [frontend tech debt epic](https://gitlab.com/groups/gitlab-org/-/work_items/24053).

## Feature flags that change the frontend

The flag definitions under `ee/config/feature_flags/` are the source of truth for state and rollout.
This list only maps each flag that changes frontend behavior to what it changes, so you know what to test with the flag on and off.
When you add a flag that affects the frontend, add it here. When you remove a flag, remove its row in the same merge request.

| Flag | What it changes in the frontend |
|------|--------------------------------|
| `secrets_manager_vulnerability_cta` | Whether the vulnerability details sidebar renders the secrets manager card. Checked per project in `secrets_helper.rb`. |
| `secrets_manager_api_access` | Whether the non-CI/CD token endpoint accepts requests. The permissions UI offers the **Read value** grant regardless, so a grant can exist before the flag lets it be used. |

Flags that only change the backend, such as the entitlement resolver's fallback behavior, are not listed here. Their effect reaches the frontend as a different state, not as different code.

## Known technical debt

The [frontend tech debt epic](https://gitlab.com/groups/gitlab-org/-/work_items/24053) tracks the refactors that are planned but not started.
Check it before you start a change to the secrets table, the error handling, or the test setup, because some of that code is scheduled to change shape.

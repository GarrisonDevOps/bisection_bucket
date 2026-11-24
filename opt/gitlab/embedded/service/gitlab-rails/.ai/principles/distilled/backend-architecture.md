---
source_checksum: fb99a3370d1401f9
distilled_at_sha: b0b7e1628f9fb689a18cee2ec91c621c6a26dd2d
---
<!-- Auto-generated from docs.gitlab.com by gitlab-ai-principles-distiller — do not edit manually -->

> **Prerequisite:** If you haven't already, also read .ai/principles/distilled/backend-ruby.md - it contains foundational rules that apply to all backend work.

# Backend Architecture Principles

## Checklist

### Abstraction Layer Usage

- DO NOT use high-level Finder classes (e.g., `ProjectsFinder`) inside other Finders; use the underlying query primitives directly
- DO NOT call `ActiveRecord` methods (e.g., `where`, `find_by`) directly from controllers, API endpoints, service classes, finders, presenters, or serializers — only from model class/instance methods
- DO NOT use Presenters or Serializers inside Service classes
- DO NOT use Service classes, Presenters, Serializers, or Workers inside Finders
- DO NOT use service classes, presenters, or serializers inside model class/instance methods
- DO NOT invoke a Worker directly with `SomeWorker.new.perform`; use `SomeWorker.perform_async` or `SomeWorker.perform_in`
- DO NOT execute database queries in views; move all data retrieval into the controller or a presenter and pass the result as an instance variable
- DO NOT put business logic in views; extract conditionals that evaluate model state beyond `nil?`, `present?`, or boolean attribute checks into a helper, presenter, or ViewComponent
- Use the abstraction table to verify that each layer only calls permitted abstractions before approving cross-layer calls
- DO NOT put business logic in workers; load records from the job arguments with `find_by_id` (return early when the record is `nil`), call one service, and keep only Sidekiq concerns (worker attributes, job-specific log metadata, retry hooks) in the worker
- Use `Gitlab::Metrics::RuntimeLimiter` (not the `LoopWithRuntimeLimit` worker concern) to limit runtime in a service

### Service Classes

- Ensure service class initializer takes the acted-upon model as the first positional argument
- Ensure service classes that act on behalf of a user include `current_user:` as a keyword argument
- Ensure the `#execute` method takes no arguments (all data passed via initializer)
- Ensure `#execute` returns a `ServiceResponse` object when a return value is needed
- Use `ServiceResponse.success` / `ServiceResponse.error` with a `message:` and optional `payload:` or `reason:`
- Use domain-specific `reason:` symbols in `ServiceResponse.error` (e.g., `:job_not_retriable`, `:duplicate_package`); use Rails HTTP status symbols only for common failures like `:not_found` or `:forbidden`
- Inherit from `BaseContainerService`, `BaseProjectService`, or `BaseGroupService` where appropriate
- DO NOT put business logic that changes application state in objects that are not service classes (use finders or value objects for read-only operations)
- Optionally include `Gitlab::Utils::Executable` to expose a class-level `execute` method when callers only need the result and not the service instance; the mixin is opt-in and `new` remains available for callers that need the instance itself

### Finders

- Ensure finder `#execute` methods return `ActiveRecord::Relation`; add exceptions to `spec/support/finder_collection_allowlist.yml` only when necessary
- DO NOT reuse other finders inside a finder

### Naming and Ubiquitous Language

- Use ubiquitous language from the product/user documentation instead of CRUD terminology when naming service classes and domain objects (e.g., `Epic::AddExistingIssueService` not `EpicIssues::CreateService`)
- Use CRUD names only when they match the existing ubiquitous language and are unambiguous (e.g., `Projects::CreateService`)
- Ensure new classes and database tables use ubiquitous language; use `self.table_name=` when model name diverges from table name

### Bounded Contexts and Namespaces

- Ensure every Ruby class is nested inside a top-level namespace present in `config/bounded_contexts.yml`; resolve `Gitlab/BoundedContexts` RuboCop offenses by nesting into an existing context
- DO NOT nest feature-specific classes under `Projects::` or `Groups::` namespaces unless the concept is strictly about projects or groups themselves
- DO NOT use stage or group names as bounded context namespaces (feature categories can be reassigned)
- Define event classes and publish events within the same bounded context (top-level Ruby namespace) where the triggering feature lives
- Place FOSS event subscriptions in `lib/gitlab/bounded_contexts/subscriptions/[context]_subscriptions.rb`; for domains that exist in both FOSS and EE, place EE code in `ee/lib/ee/gitlab/event_store/subscriptions/[context]_subscriptions.rb`; EE-only domains in `ee/lib/gitlab/event_store/subscriptions/[context]_subscriptions.rb`
- Add newly created subscription groups to the `SUBSCRIPTION_GROUPS` constant in `lib/gitlab/event_store.rb` (or `EE_SUBSCRIPTION_GROUPS` in `ee/lib/ee/gitlab/event_store.rb` for EE)

### Omniscient Classes

- DO NOT add new methods or data to omniscient classes (`Project`, `User`, `MergeRequest`, `Ci::Pipeline`, or any class >1000 LOC); create a dedicated class instead
- Prefer thin domain wrapper objects (e.g., `AntiAbuse::UserTrustScore.new(user)`) over adding methods to large models
- Use dependency inversion to encapsulate related behavior in a bounded context rather than adding it to a shared model
- DO NOT move methods out of an omniscient class into a mixin or `ActiveSupport::Concern`; use a dedicated composed class in the bounded context that receives the record or its ID
- DO NOT add methods to `Project`, `Group`, `User`, or `Organizations::Organization` (or their `EE::` counterparts) or to the `intrinsic_methods.yml`/`legacy_methods.yml` files under `rubocop/cop/gitlab/config/omniscient_classes/` (enforced by the `Gitlab/OmniscientClassMethods` RuboCop cop); when moving or removing a method, also remove it from `legacy_methods.yml`

### Use-Case-Oriented Design

- DO NOT reuse a single service class for radically different use cases with different permissions, preconditions, or side-effects; create separate service classes per use case
- Ensure each service class enforces a single, cohesive set of permissions and parameters

### EventStore

- Use Cloud Events (inheriting from `Gitlab::EventStore::CloudEvent`) for all new events; DO NOT create new legacy `Gitlab::EventStore::Event` subclasses (enforced by the `Gitlab/EventStoreCloudEventInheritance` RuboCop cop)
- Define Cloud Event classes under `app/events/<namespace>/`; set `event_category` and `event_type` via class-level methods and implement `data_schema` returning a valid JSON Schema for the `data` field
- Name events in past tense: `<DomainObject><Action>Event` (e.g., `Ci::PipelineCreatedEvent`, not `Ci::CreatePipelineEvent`); elide the domain object when obvious from the bounded context (e.g., `MergeRequest::ApprovedEvent` not `MergeRequest::MergeRequestApprovedEvent`)
- Design events to be semantic (describe what occurred, not the intended subscriber action), specific (narrowly defined, use properties for additional info), and scoped (only publish events about domain objects within your bounded context)
- Define event schemas as valid JSON Schema; mark unique identifiers as `required` and all other properties as optional
- Publish only properties needed by subscribers; DO NOT tailor the payload to a specific subscriber
- Dispatch events from service classes; use model state machine transitions as an exception, not `ActiveRecord` callbacks
- DO NOT publish events about domain objects outside your bounded context
- Introduce new Sidekiq subscriber workers in a prior deployment (or behind a feature flag) before registering the subscription
- Use conditional dispatch (`if:` lambda) only for cheap synchronous checks; handle complex conditions inside `handle_event`
- Access Cloud Event envelope fields (e.g., `current_user`, `organization`) directly on the event object; access custom payload via `event.event_data`
- Follow the multi-rollout process when renaming events, adding required properties, or removing properties (expand → migrate → contract across separate milestones)
- Use `publish_event` RSpec matcher to test publishers; use `it_behaves_like 'subscribes to event'` shared example to test subscribers; use `it_behaves_like 'a cloud event with schema'` shared example to validate Cloud Event `data_schema`
- Define CE events and publish them in CE code; define EE events and publish them in EE code; subscribers may cross CE/EE boundaries
- DO NOT use EventStore when logic must run synchronously as part of the main business transaction rather than as a side-effect
- Use `Gitlab::EventStore.publish_group` when publishing multiple events of the same type in a single transaction to reduce Sidekiq load; configure `group_size` on the subscription as needed
- Consider configuring a concurrency limit on subscriber workers if there is a risk of saturating shared resources

### Modules and Instance Variables

- DO NOT share instance variables across multiple mixed-in modules; keep instance variables contained within the module that owns them
- Prefer the `@var ||= value` single-assignment pattern when memoizing in a module
- DO NOT use instance variables in view partials; pass locals explicitly and fetch with `local_assigns.fetch(:key)`

### Abstract Methods

- Use `Gitlab::AbstractMethodError` (not `NotImplementedError`, `NoMethodError`, or a generic string `raise`) for abstract methods that subclasses must implement
- Prefer composition and duck typing over inheritance; use abstract methods only for framework integration points or shared-template components (e.g., ViewComponents)

### Application Limits

- Add new plan limits as a column in `plan_limits` with a non-null default, then fine-tune per plan using `create_or_update_plan_limit` in a separate migration
- Cover all GitLab.com plans (`default`, `free`, `premium`, `premium_trial`, `ultimate`, `ultimate_trial`, `ultimate_trial_paid_customer`, `opensource`) in limit migrations; omitting a plan causes those customers to receive the default (possibly `0`/unlimited)
- Expose every new plan limit column through the admin Plan Limits API by adding it as an `optional` parameter on `PUT /application/plan_limits` and to the response entity in `lib/api/entities/plan_limit.rb`; `plan_limits` is cell-scoped configuration, so this API is the only way administrators can tune limits per cell
- Use `PlanLimits#exceeded?` or the `Limitable` concern to enforce limits; DO NOT implement ad-hoc count checks
- Use a LabKit request rate limit (`Gitlab::Middleware::LabkitRackRateLimit`) for limits that protect a group of routes by IP or requester, and `Gitlab::ApplicationRateLimiter` for limits on a single action, resource-based or distinct-resource counts, or work outside a web request; use `Gitlab::ApplicationRateLimiter` when either would work. DO NOT expect `Rack::Attack` to throttle requests — it remains in the middleware stack but LabKit enforces limits
- Add a request rate limit by: adding fields to `ApplicationSetting`'s `rate_limits` JSONB column, updating the JSON schema validator, adding a throttle definition (`Gitlab::RackAttack.throttle_definitions` with a predicate in `Gitlab::RackAttack::Request`, or one `Gitlab::Throttle::REGULAR_THROTTLES` entry for an authenticated/unauthenticated pair), registering it in `ThrottleRegistry` (a spec fails otherwise), adding the Admin area form settings, and documenting the new settings
- Make every new rate limit configurable through an application setting; if it must be non-configurable, explain why in the MR and document that exception. Add defaults to `ApplicationSetting.rate_limits_definition` (or its EE override), expose the fields through `ApplicationSettingsHelper#visible_attributes`, and declare typed, described `optional` API parameters in `lib/api/settings.rb` (or `ee/lib/ee/api/helpers/settings_helpers.rb` for EE-only limits). Document the attributes in the settings API.
- Validate an application rate limiter setting with `greater_than_or_equal_to: 0` and JSON schema `minimum: 0` (zero disables it); validate LabKit request counts and periods with `greater_than: 0` and `minimum: 1`, and declare the enabled field as boolean. Read the setting in the application limiter's `limit` lambda or through `Gitlab::Throttle.settings` for a request throttle.
- In `ThrottleRegistry` entries, use `ThrottleRegistry::GENERAL` as the `limiter` unless the throttle counts requests another general rule also counts; use an existing `cohort`; declare `claims` on every entry; in `match`, gate nullable characteristics on presence (e.g., `requester_id: /./`), include the throttle's `setting_*` fact, and put the `path:` regular expression last
- Register a `Gitlab::ApplicationRateLimiter` key in `SupportedRateLimits` with a `limit_`-prefixed name and `action: :limit`; for a new key in log-mode rollout, use `staged_rule` instead, which supplies the action.
- Check a key with `check_rate_limit!` from `CheckRateLimit` in Rails controllers or `API::Helpers::RateLimiter` in Grape endpoints; use `rate_limit` from `RateLimitedService` in services. In GraphQL mutations, call `Gitlab::ApplicationRateLimiter.throttled?` and raise `RateLimitedService::RateLimitedError` when throttled; in workers, models, and library code, call `throttled?` and handle the result. Call `throttled_request?` directly only when a request cannot use a helper.
- Pass `scope:` keyed by the rule's characteristic names, which are bare nouns without an `_id` suffix (e.g., `:user`, `:project`); DO NOT pass unregistered scope keys, which raise in development and test; for global limits, use `scope: { scope: :global }` (the repeated name is intentional); DO NOT rename an existing characteristic, since it starts a new Redis counter
- In `RateLimitedService`, map the rule's characteristic names to the service methods that provide their values (e.g., `rate_limit key: :issues_create, opts: { scope: { project: :project, user: :current_user } }`)
- Choose rate-limit rollout by key type: use `staged_rule` only for a new `Gitlab::ApplicationRateLimiter` key, with a literal flag name and `default_enabled: false`. Gate enforcement on a characteristic every caller supplies in `scope:`; a `nil` actor prevents actor-list and percentage-of-actors rollout for that call. An instance-wide `enforce` lambda must accept exactly one argument (`->(_scope) { Feature.enabled?(:flag, :instance) }`), or `staged_rule` raises `ArgumentError`. After rollout, replace `staged_rule` with `Labkit::RateLimit::Rule.new`, set `action: :limit`, and remove the flag.
- For an existing key with an instance-wide switch, return `0` from its `limit` lambda while the flag is off and check the flag against `:instance` only. For an existing key with a per-actor gate, check the flag before the rate-limit check at every call site; for `RateLimitedService`, gate inside the service or have each caller use `execute_without_rate_limiting` while disabled. LabKit request throttles use dry run mode instead of a new rollout flag.

### Backwards Compatibility Across Updates

- Follow the expand-and-contract pattern for breaking changes: expand (backward-compatible addition) → migrate (update consumers) → contract (remove old code) across separate milestones
- DO NOT bundle expand and migrate phases into the same milestone for Sidekiq worker parameter changes (Puma may restart before Sidekiq, causing job failures)
- Ensure new GraphQL fields or REST API fields added in release N are not used by frontend code until release N+1 (or are behind a default-disabled feature flag, or degrade gracefully)
- DO NOT add a `NOT NULL` column constraint without a default value when old application nodes are still inserting rows without that column
- Ensure route changes follow expand-and-contract: add new route first, then generate new-format links, then remove old route

### Cells Compatibility

- Design all new code with Cells compatibility in mind; follow the [Cells development principles](https://docs.gitlab.com/development/cells/)
- DO NOT introduce plan limits that must stay consistent across cells — `plan_limits` is cell-scoped configuration and is not migrated between cells

### CE/EE Code Separation

- CE code (outside `ee/`) must not directly reference `EE::` namespaced classes
- EE extensions use `prepend_mod` pattern in CE files
- If CE code needs EE-aware behavior, use `prepend_mod` hooks or `Gitlab.ee?` guards
- Flag direct references to `EE::` namespaced classes in CE code (prevents FOSS build failures)

### ActiveRecord Callbacks

- Callbacks should only modify data on the current model, not associated records
- Question if callback logic should be in a service layer instead
- Flag callbacks with side effects (external API calls, updating other records, complex business logic)
- Flag bulk operations on associated records in callbacks (performance concern as associations grow)
- Acceptable uses: data normalization on current model only (trimming whitespace, setting defaults)

### Authorization

- Before changing authorization logic, read the existing `authorize!` / `authorize_admin!` call and verify what permission it currently enforces; the required fix may be documentation- or test-only with no code change needed

## Authoritative sources

For the full picture, see:

- doc/development/reusing_abstractions.md
- doc/development/software_design.md
- doc/development/eventstore/_index.md
- doc/development/module_with_instance_variables.md
- doc/development/application_limits.md
- doc/development/multi_version_compatibility.md


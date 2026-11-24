---
stage: Async
group: Async
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Application limits development
---

This document provides a development guide for contributors to add application
limits to GitLab.

## Documentation

First of all, you have to gather information and decide which are the different
limits that are set for the different GitLab tiers. Coordinate with others to document
and communicate those limits.

Add the documentation to the page that matches the limit type:

- [Plan limits and other instance-wide limits](../administration/instance_limits.md).
- Rate limits that are:
  - [Configurable in the **Admin** area](../rate_limits/_index.md#admin-area).
  - [Configurable only with the API or the Rails console](../rate_limits/_index.md#api-and-rails-console).
  - [Not configurable](../rate_limits/non_configurable.md).

There is a guide about [introducing application limits](https://handbook.gitlab.com/handbook/product/product-processes/#introducing-application-limits).

## Implement plan limits

The `plan_limits` table is cell-scoped configuration: each cell has its own
copy of the table, and limits are not migrated between cells. New cells start
with the column default for each limit, and administrators tune limits per cell
via the [admin Plan Limits API](../api/plan_limits.md). Because of this, every
new plan limit must be settable through that API - otherwise a new limit
can only ever take its column default on each cell.

Do not introduce a plan limit that must stay consistent across cells -
`plan_limits` is cell-local, so there is no way to keep it in sync.

### Insert database plan limits

In the `plan_limits` table, create a new column and insert the limit values.
It's recommended to create two separate migration script files.

1. Add a new column to the `plan_limits` table with non-null default value that
   represents desired limit, such as:

   ```ruby
   add_column(:plan_limits, :project_hooks, :integer, default: 100, null: false)
   ```

   Plan limits entries set to `0` mean that limits are not enabled. You should
   use this setting only in special and documented circumstances.
1. (Optionally) Create the database migration that fine-tunes each level with a
   desired limit using the `create_or_update_plan_limit` migration helper.
   The plans in this migration should match the [plans on GitLab.com](#subscription-plans).
   If a plan is missed, customers on that plan would receive the default limit, which might be
   `0` (unlimited).

   For example:

   ```ruby
   class InsertProjectHooksPlanLimits < Gitlab::Database::Migration[2.1]
     def up
       create_or_update_plan_limit('project_hooks', 'default', 0)
       create_or_update_plan_limit('project_hooks', 'free', 10)
       create_or_update_plan_limit('project_hooks', 'premium', 30)
       create_or_update_plan_limit('project_hooks', 'premium_trial', 30)
       create_or_update_plan_limit('project_hooks', 'ultimate', 100)
       create_or_update_plan_limit('project_hooks', 'ultimate_trial', 100)
       create_or_update_plan_limit('project_hooks', 'ultimate_trial_paid_customer', 100)
       create_or_update_plan_limit('project_hooks', 'opensource', 100)
     end

     def down
       create_or_update_plan_limit('project_hooks', 'default', 0)
       create_or_update_plan_limit('project_hooks', 'free', 0)
       create_or_update_plan_limit('project_hooks', 'premium', 0)
       create_or_update_plan_limit('project_hooks', 'premium_trial', 0)
       create_or_update_plan_limit('project_hooks', 'ultimate', 0)
       create_or_update_plan_limit('project_hooks', 'ultimate_trial', 0)
       create_or_update_plan_limit('project_hooks', 'ultimate_trial_paid_customer', 0)
       create_or_update_plan_limit('project_hooks', 'opensource', 0)
     end
   end
   ```

   Some plans exist only on GitLab.com. This is a no-op for plans
   that do not exist.

   To set limits in your migration only for GitLab.com and allow other instances
   to use the default limits, add `return unless Gitlab.com?` to the start of
   the `#up` and `#down` methods to make the migration a no-op for other instances.
1. Expose the new column through the [admin Plan Limits API](../api/plan_limits.md):

   - Add it as an `optional` parameter on `PUT /application/plan_limits`
     ([`lib/api/admin/plan_limits.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/api/admin/plan_limits.rb))
     so administrators can tune the limit per cell.
   - Add it to the response entity
     ([`lib/api/entities/plan_limit.rb`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/api/entities/plan_limit.rb))
     so the limit can be read back.
   - Document the attribute on the [Plan Limits API page](../api/plan_limits.md).

### Plan limits validation

#### Get current limit

Access to the current limit can be done through the project or the namespace,
such as:

```ruby
project.actual_limits.project_hooks
```

#### Check current limit

There is one method `PlanLimits#exceeded?` to check if the current limit is
being exceeded. You can use either an `ActiveRecord` object or an `Integer`.

Ensures that the count of the records does not exceed the defined limit, such as:

```ruby
project.actual_limits.exceeded?(:project_hooks, ProjectHook.where(project: project))
```

Ensures that the number does not exceed the defined limit, such as:

```ruby
project.actual_limits.exceeded?(:project_hooks, 10)
```

#### `Limitable` concern

The [`Limitable` concern](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/concerns/limitable.rb)
can be used to validate that a model does not exceed the limits. It ensures
that the count of the records for the current model does not exceed the defined
limit.

You must specify the limit scope of the object being validated
and the limit name if it's different from the pluralized model name.

```ruby
class ProjectHook
  include Limitable

  self.limit_name = 'project_hooks' # Optional as ProjectHook corresponds with project_hooks
  self.limit_scope = :project
end
```

To test the model, you can include the shared examples.

```ruby
it_behaves_like 'includes Limitable concern' do
  subject { build(:project_hook, project: create(:project)) }
end
```

### Testing instance-wide limits

Instance-wide features always use `default` Plan, as instance-wide features
do not have license assigned.

```ruby
class InstanceVariable
  include Limitable

  self.limit_name = 'instance_variables' # Optional as InstanceVariable corresponds with instance_variables
  self.limit_scope = Limitable::GLOBAL_SCOPE
end
```

### Subscription Plans

GitLab Self-Managed:

- `default`: Everyone.

GitLab.com:

- `default`: Any system-wide feature.
- `free`: Namespaces and projects with a Free subscription.
- `premium`: Namespaces and projects with a Premium subscription.
- `premium_trial`: Namespaces and projects with a Premium Trial subscription.
- `ultimate`: Namespaces and projects with an Ultimate subscription.
- `ultimate_trial`: Namespaces and projects with an Ultimate Trial subscription.
- `ultimate_trial_paid_customer`: Namespaces and projects on a Premium subscription that are trialling Ultimate for 30 days.
- `opensource`: Namespaces and projects that are member of GitLab Open Source program.

There is an `early_adopter` plan on GitLab.com that has no subscriptions.

The `test` environment doesn't have any plans.

## Add a rate limit

GitLab has two rate limiters for application code.
Both use the [LabKit rate limiting SDK](https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/lib/labkit/rate_limit/README.md) and store their counters in the rate limiting Redis instance.

To add a rate limit:

1. [Choose a rate limiter](#choose-a-rate-limiter).
1. [Make the rate limit configurable](#make-a-rate-limit-configurable).
   Every new rate limit needs an application setting.
1. Register the limit as a [request rate limit with LabKit](#implement-request-rate-limits-with-labkit)
   or as a [`Gitlab::ApplicationRateLimiter` key](#implement-rate-limits-using-gitlabapplicationratelimiter).
1. For a `Gitlab::ApplicationRateLimiter` key, [check the rate limit](#check-a-rate-limit)
   from the code that performs the action.
1. [Roll out the rate limit behind a feature flag](#roll-out-a-rate-limit-behind-a-feature-flag).
1. [Document the rate limit](#documentation).

## Choose a rate limiter

Add a request rate limit with LabKit when:

- The limit protects a group of routes from request volume, whatever action each request performs.
  For example, the packages API, the files API, or Git over HTTP.
- The limit counts by IP address or by the authenticated requester.
- The request should be blocked before it reaches a controller or Grape endpoint.

Add a `Gitlab::ApplicationRateLimiter` key when:

- The limit applies to one action, such as creating an issue or sending an email.
- The limit counts by a resource, such as a project, group, or namespace, or by a combination of values.
- The limit counts distinct resources, or the work runs outside a web request, such as in a Sidekiq worker.

If either rate limiter could work, use `Gitlab::ApplicationRateLimiter`.
Its limit applies only to the action that calls it.

## Make a rate limit configurable

A rate limit needs an application setting, so that administrators can raise, lower, or disable
the limit without a code change.
If a limit must not be configurable, state the reason in the merge request and document the
limit as a non-configurable rate limit.

New rate limit settings are fields in the `rate_limits` JSONB column of `ApplicationSetting`.
Older throttle settings are table columns.
To add a setting:

1. Add the fields and their defaults to `ApplicationSetting.rate_limits_definition` in
   `app/models/application_setting.rb`. For an EE-only limit, add them to the EE override in
   `ee/app/models/ee/application_setting.rb`.
   - A `Gitlab::ApplicationRateLimiter` key has one integer field:

     ```ruby
     discussions_resolve_limit: [:integer, { default: 120 }],
     ```

   - A LabKit request throttle has a boolean field and two integer fields:

     ```ruby
     throttle_authenticated_mcp_enabled: [:boolean, { default: false }],
     throttle_authenticated_mcp_requests_per_period: [:integer, { default: 600 }],
     throttle_authenticated_mcp_period_in_seconds: [:integer, { default: 60 }],
     ```

1. Validate the integer fields in the same model, which has two `with_options(numericality: ...)` blocks:
   - Add a `Gitlab::ApplicationRateLimiter` limit to the `greater_than_or_equal_to: 0` block,
     because `0` disables the key.
   - Add the LabKit `requests_per_period` and `period_in_seconds` fields to the `greater_than: 0` block.
1. Add the fields to the JSON schema in
   `app/validators/json_schemas/application_setting_rate_limits.json`:
   - A `Gitlab::ApplicationRateLimiter` limit is an `integer` with `"minimum": 0`.
   - The LabKit `requests_per_period` and `period_in_seconds` fields are an `integer` with
     `"minimum": 1`, and the `enabled` field is a `boolean`.
1. Add the setting to `ApplicationSettingsHelper#visible_attributes` in
   `app/helpers/application_settings_helper.rb`, or to the EE override in
   `ee/app/helpers/ee/application_settings_helper.rb` for an EE-only limit.
   This list exposes the setting on the application settings API for reading and writing, and
   permits it in the Admin area controller.
   For the full procedure, see [application settings](application_settings.md).
1. Add an `optional` parameter with `type:` and `desc:` in `lib/api/settings.rb`, or in
   `ee/lib/ee/api/helpers/settings_helpers.rb` for an EE-only limit, so the API validates the
   value and the OpenAPI document describes it.
   Document the attribute in the [application settings API](../api/settings.md).
1. Optional. Add a form field to the matching partial in `app/views/admin/application_settings/`.
1. Read the setting from the limit:
   - In a `Gitlab::ApplicationRateLimiter` key, set `limit` to a lambda that reads the setting.

     ```ruby
     limit: -> { Gitlab::CurrentSettings.current_application_settings.discussions_resolve_limit },
     ```

   - In a LabKit request throttle, read the settings through `Gitlab::Throttle.settings` in the
     throttle definition.

## Implement request rate limits with LabKit

The `Gitlab::Middleware::LabkitRackRateLimit` middleware rate limits Rails controllers,
Grape endpoints, and any other Rack requests.
The middleware runs after Warden authenticates the request and before the request reaches the application.
A request over the limit receives a `429 Too Many Requests` response.

LabKit enforces these rate limits.
`Rack::Attack` is still in the middleware stack, but it does not throttle requests.
LabKit reads each limit and period from the throttle definitions in `Gitlab::RackAttack`,
so new throttles still start there.

To add a request rate limit:

1. [Make the rate limit configurable](#make-a-rate-limit-configurable).
1. Add a throttle definition, which holds the limit and period:
   - For a single throttle, add it to `Gitlab::RackAttack.throttle_definitions`,
     with a matching predicate in `Gitlab::RackAttack::Request`.
   - For an authenticated and unauthenticated pair, add one entry to `Gitlab::Throttle::REGULAR_THROTTLES`.
     `Gitlab::RackAttack.regular_throttle_definitions` generates `throttle_unauthenticated_<name>`
     and `throttle_authenticated_<name>` from it.
1. Register the throttle in `ThrottleRegistry`. For more information, see [register a throttle](#register-a-throttle).
1. Add the new settings to the **Admin** area form in `app/views/admin/application_settings/_ip_limits.html.haml`.
1. Optional. To observe the throttle before it blocks requests, name it in the
   [`GITLAB_THROTTLE_DRY_RUN` environment variable](../administration/settings/user_and_ip_rate_limits.md#try-out-throttling-settings-before-enforcing-them).
   A throttle in dry run mode builds as a [`:log` rule](https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/lib/labkit/rate_limit/README.md#actions) instead of a `:limit` rule,
   and its claim is named `<rule_name>_dry_run_bypass` instead of `<rule_name>_claim`.
1. Document the new settings in [User and IP rate limits](../administration/settings/user_and_ip_rate_limits.md).
1. Configure the rate limit for GitLab.com and document it in [rate limits on GitLab.com](../user/gitlab_com/rate_limits.md).

### Register a throttle

Each throttle maps to one LabKit rule in `Gitlab::RackAttack::LabkitRateLimit::ThrottleRegistry`,
defined in `lib/gitlab/rack_attack/labkit_rate_limit/throttle_registry.rb` and, for EE throttles, in
`ee/lib/ee/gitlab/rack_attack/labkit_rate_limit/throttle_registry.rb`.
A spec fails if a throttle in `Gitlab::RackAttack.all_throttle_definitions` has no registry entry.

Each entry declares:

- `limiter`: The limiter that owns the rule. Use `ThrottleRegistry::GENERAL`, unless the throttle
  must count requests that a rule in the general limiter also counts.
  In one limiter, a request is counted by the first rule that claims it, so a throttle that
  counts the same requests as another rule needs its own limiter.
  The protected paths and EE incident management throttles have their own limiters for this reason.
- `characteristics`: What the rule counts by, for example `[:ip]` for an unauthenticated
  throttle or `[:requester_type, :requester_id]` for an authenticated throttle.
- `match`: The facts a request must have for the rule to apply.
- `cohort`: The rollout cohort whose feature flags control enforcement of the rule.
  Use an existing cohort. A new cohort needs its own feature flag definitions, and
  `Rack::Attack` throttles requests again until both flags for the new cohort are enabled.
- `claims`: Whether the rule stops evaluation after it counts a request. Every entry must
  declare it.

LabKit evaluates the skip rules first, such as the bypass header and the user allowlist,
then the GitLab.com plan rules, then the registry rules.
Registry rules are evaluated in registry order: specialized APIs, then Git, then web,
then the general API. A throttle with `claims: true` counts the request and stops evaluation,
so a more general rule later in the list does not count the same request.

A claim includes the throttle's `setting_*` fact, so ordering excludes a request only while the
claiming throttle is enabled. For an exclusion that must always apply, add a [negated fact](https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/lib/labkit/rate_limit/README.md#matchers) to
`match`, as the web and API rules do with `path: { nre: <regex> }`, `git_http_non_lfs: false`,
and `frontend: false`.

In `match`:

- Gate the rule on the presence of each characteristic that can be `nil`. An authenticated rule
  gates on `requester_id: /./`, and a rule that counts by `[:aid]` gates on `aid: /./`.
  Without the gate, requests with no value share one counter.
- Gate an unauthenticated rule on `requester_id: nil, runner_id: nil`.
- Include the throttle's `setting_*` fact, so that disabling the throttle in the **Admin**
  area stops the rule from matching.
- Put the `path:` regular expression last. Conditions are checked in order and evaluation
  stops at the first one that fails, so cheaper conditions first avoid running the regular
  expression.

Rules match on the facts returned by
`Gitlab::RackAttack::LabkitRateLimit::ClassifiedRequest#labkit_facts`, which merges the
identity facts with the classification facts. Add the throttle's `setting_*` fact to
`ClassifiedRequest#classification_facts`, or to the EE module for an EE throttle.
Add a classification fact only for a condition that a path regular expression cannot express.

### Tier-aware request rate limits

On GitLab.com, `Gitlab::RateLimit::PlanRules` adds request rate limits that depend on the
subscription plan of the requester. These rules are defined in
`ee/lib/ee/gitlab/rate_limit/plan_rules.rb` and apply only to GitLab.com.

- Each limit has two rules: a `:log` rule that counts requests, and a `:limit` rule that
  blocks them. Feature flags with `_info` and `_enforce` suffixes decide which rule matches.
- An authenticated user gets the highest plan among the top-level groups the user is a member of,
  directly or through a shared group. A user with no paid group gets the Free limits.

## Implement rate limits using `Gitlab::ApplicationRateLimiter`

`Gitlab::ApplicationRateLimiter` limits a single action. Call it from the code that performs the
action, such as a controller, API endpoint, service, or worker.
Each rate limit key is a LabKit rule.

### Add a rate limit key

1. Add a `Labkit::RateLimit::Rule` for the key to `Gitlab::ApplicationRateLimiter::LabkitAdapter::SupportedRateLimits`.
   CE keys are in `lib/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb`,
   and EE-only keys and EE overrides are in
   `ee/lib/ee/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb`.
   A key with no rule raises `Gitlab::ApplicationRateLimiter::InvalidKeyError`.

   ```ruby
   issues_create: ::Labkit::RateLimit::Rule.new(
     name: 'limit_issues_by_project_user_external_author',
     characteristics: %i[project user external_author],
     limit: -> { Gitlab::CurrentSettings.current_application_settings.issues_create_limit },
     period: 1.minute,
     action: :limit
   ),
   ```

1. Set the rule attributes.
   For what each attribute does, see [Rule](https://gitlab.com/gitlab-org/ruby/gems/labkit-ruby/-/blob/master/lib/labkit/rate_limit/README.md#rule) in the LabKit documentation.
   In GitLab:
   - `name` must start with `limit_`. A spec fails for a name without the prefix.
   - `action` must be `:limit`. To roll out a new key in log mode first, define it with `staged_rule`
     instead, which sets `action` itself. See [roll out a key in log mode](#roll-out-a-gitlabapplicationratelimiter-key-in-log-mode).
   - `limit` is a lambda that reads the application setting for the limit.
   - `characteristics` use the names in [characteristic names](#characteristic-names).
   - `count_distinct` is optional. Set to `:project_id` to count distinct resources passed as
     `resource:` instead of counting calls. For an example, see the EE
     `unique_project_downloads_for_application` key in
     `ee/lib/ee/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb`.
1. Check the key from the code that performs the action.

A spec requires every key to define a limit and a period. Keys that receive their limit from
the caller, or count a cost instead of calls, are listed as exceptions in
`spec/lib/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits_spec.rb`.

### Check a rate limit

Check the rate limit from the code that performs the action.
Each code path has one entry point:

| Code path                              | Entry point                                                                                       |
|----------------------------------------|---------------------------------------------------------------------------------------------------|
| Rails controller                       | `check_rate_limit!` from the `CheckRateLimit` concern, which `ApplicationController` includes.    |
| Grape API endpoint                     | `check_rate_limit!` from `API::Helpers::RateLimiter`, which `API::API` includes.                  |
| Service                                | `rate_limit` from the `RateLimitedService` concern.                                               |
| GraphQL mutation                       | `Gitlab::ApplicationRateLimiter.throttled?`, then raise `RateLimitedService::RateLimitedError`.   |
| Sidekiq worker, model, or library code | `Gitlab::ApplicationRateLimiter.throttled?`.                                                      |

Every entry point takes the key and a `scope:` hash keyed by the characteristic names the key
registers in `SupportedRateLimits`:

```ruby
Gitlab::ApplicationRateLimiter.throttled?(:issues_create, scope: { project: project, user: current_user })
```

ActiveRecord values contribute their primary key and primitives their string
form. Omitted (or `nil`) characteristics are keyed on labkit's `_unknown_`
sentinel, and a scope key that is not a characteristic of the rule raises in
development and test.

#### Rails controllers

`check_rate_limit!` calls `Gitlab::ApplicationRateLimiter.throttled_request?`, which honors the
rate limit bypass header and logs a throttled request to `auth.log` with the message
`Application_Rate_Limiter_Request`.
When the action is over the limit, the method renders the error message with `429 Too Many Requests`.
Pass `redirect_back: true` to redirect to the previous page with the message as an alert instead.
A block replaces the response:

```ruby
check_rate_limit!(:raw_blob, scope: { project: @project, path: @path }) do
  render plain: _('You cannot access the raw file. Please wait a minute.'), status: :too_many_requests
end
```

#### Grape API endpoints

The Grape `check_rate_limit!` also calls `throttled_request?`.
When the action is over the limit, the method responds with `429 Too Many Requests` and a
`RateLimit-Name` header set to the key.
The `Retry-After` header is the `interval:` option when the call passes one, and the period of the
key otherwise.
Pass `message:` to replace the error message.
A block runs before the response and does not replace it.

`check_rate_limit_by_user_or_ip!` scopes the limit by `current_user` for an authenticated request,
and by IP address otherwise:

```ruby
check_rate_limit_by_user_or_ip!(:<key>)
```

#### Services

Prepend `RateLimitedService` and declare the key.
The `scope` in `opts:` maps each characteristic to the service method that supplies its value:

```ruby
prepend RateLimitedService

rate_limit key: :issues_create,
  opts: { scope: { project: :project, user: :current_user } }
```

`execute` checks the limit first, and raises `RateLimitedService::RateLimitedError` when
the action is over the limit.
`ApplicationController` and `API::API` rescue the error, log the request, and respond with
`429 Too Many Requests`. `GraphqlController` responds with the same status.
To run the service without the check, call `execute_without_rate_limiting` instead of `execute`.

#### GraphQL mutations, workers, and library code

Call `Gitlab::ApplicationRateLimiter.throttled?`, which counts the action and returns `true` when
the action is over the limit.
In a GraphQL mutation, raise `RateLimitedService::RateLimitedError`, which `GraphqlController`
turns into a `429 Too Many Requests` response:

```ruby
def check_rate_limit!
  return unless ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { user: current_user })

  raise ::RateLimitedService::RateLimitedError.new(
    key: RATE_LIMIT_KEY, rate_limiter: ::Gitlab::ApplicationRateLimiter
  ), ::Gitlab::ApplicationRateLimiter.throttled_error_message
end
```

Elsewhere, decide what the code does when the action is over the limit, such as skipping the
work or dropping the event.

#### Other check methods and options

`Gitlab::ApplicationRateLimiter` has other methods for cases the entry points do not cover:

- `throttled_request?`: What the controller and Grape helpers call. Call it directly when you
  have a request but cannot use a helper.
- `peek`: Returns whether the action is over the limit, without counting it.
- `resource_usage_throttled?`: Adds a cost, such as database duration, instead of one call.
  The Sidekiq resource usage middleware uses it.

`throttled?` and the helpers accept these options:

- `threshold:` and `interval:` override the registered limit and period for one call.
  The `limit` or `period` of the key must be a lambda that takes a context argument, such as
  `->(ctx) { ctx&.dig(:threshold) || 100 }`. Otherwise the call raises `ArgumentError`.
- `users_allowlist:` is a list of usernames the limit does not apply to, merged with the users
  named by `GITLAB_THROTTLE_USER_ALLOWLIST`. The scope must include `user`.
  In `RateLimitedService`, pass a lambda that returns the list, because the concern calls it.
- `resource:` is the record to count for a `count_distinct` key.
- `cost:` charges a batch of actions in one call to a key that counts calls.

### Characteristic names

Each rate limit key registers an ordered list of characteristics.
Names are bare nouns: `:user`, `:project`, `:ip`, `:group`, `:namespace`. They
are never suffixed with `_id`, even though an ActiveRecord value contributes its
primary key.

Limits that are global rather than per-actor register a single characteristic
literally named `scope`, so the call reads `scope: { scope: :global }`:

```ruby
Gitlab::ApplicationRateLimiter.throttled?(:fetch_google_ip_list, scope: { scope: :global })
```

The repetition is the characteristic name colliding with the keyword argument
name. It is not a mistake.

A characteristic name is part of the Redis key. Renaming one starts a new
counter and discards whatever the old one had accumulated, so treat renames as a
behavior change rather than a refactor.

## Roll out a rate limit behind a feature flag

Roll out a new rate limit behind a [feature flag](feature_flags/_index.md), so that you can enable
the limit for a few actors first and disable it without a deployment.
The [process for managing limits on GitLab.com](https://handbook.gitlab.com/handbook/engineering/infrastructure-platforms/rate-limiting/managing-limits/)
asks for a rollout plan for every new limit.

Choose the first option that applies:

1. **New `Gitlab::ApplicationRateLimiter` key.** Define it with `staged_rule`, which runs the key
   in log mode until the flag is enabled and takes any value in the caller's `scope:` as the flag
   actor, so call sites do not change.
   For more information, see [roll out a key in log mode](#roll-out-a-gitlabapplicationratelimiter-key-in-log-mode).
   An instance-wide gate still takes one argument, `enforce: ->(_scope) { ::Feature.enabled?(:flag, :instance) }`,
   because `staged_rule` raises `ArgumentError` for any other arity.
1. **Existing key, instance-wide switch.** Return `0` from the `limit` lambda while the flag is
   disabled. `Gitlab::ApplicationRateLimiter` returns `false` before counting when the limit is
   `0`, so this disables the key with no caller change.
   The lambda receives no user or project, so the flag is checked with `:instance` only, and
   actor lists or percentage-of-actors rollouts do not apply.
   The `issuable_csv_import` key uses this pattern:

   ```ruby
   limit: -> {
     next 0 unless ::Feature.enabled?(:issuable_csv_import_rate_limit, :instance)

     Gitlab::CurrentSettings.current_application_settings.issuable_csv_import_limit
   },
   ```

1. **Existing key, per-actor gate.** Check the flag at the call site, before the rate limit check:

   ```ruby
   def check_create_rate_limit!
     return unless Feature.enabled?(:namespace_create_rate_limit, current_user)

     check_rate_limit!(:groups_create, scope: { user: current_user })
   end
   ```

   Every call site needs the check. A `RateLimitedService` key runs its check in `execute`, so
   the gate goes in the service, or each caller must choose `execute_without_rate_limiting`.
1. **LabKit request throttle.** No flag. A throttle can run in dry run mode instead.
   For more information, see [register a throttle](#register-a-throttle).

When you document the rate limit, include the flag.
For more information, see [document features deployed behind feature flags](documentation/feature_flags.md).

### Roll out a `Gitlab::ApplicationRateLimiter` key in log mode

Use log mode to see which requests a new key would block before you enforce the limit.
Define the key with `staged_rule` instead of `Labkit::RateLimit::Rule.new`, and gate
enforcement with a feature flag.
The registry checks the flag, so the call site does not change and does not check it.
Tier-aware request rate limits use the same `:log` and `:limit` rule pattern.
For more information, see [tier-aware request rate limits](#tier-aware-request-rate-limits).

`staged_rule` takes the same attributes as a rule, without `action`, and an `enforce` lambda:

```ruby
widgets_export: staged_rule(
  enforce: ->(scope) { ::Feature.enabled?(:widgets_export_rate_limit_enforce, scope[:project]) },
  name: 'limit_widgets_exports_by_project_user',
  characteristics: %i[project user],
  limit: -> { Gitlab::CurrentSettings.current_application_settings.widgets_export_limit },
  period: 1.minute
),
```

`staged_rule` registers two rules with the same limit, period, and characteristics.
The return value of `enforce` decides which rule applies to a request:

- `true`: A `:limit` rule with the given name counts the request and blocks it when it is over the limit.
- Any other value: A `:log` rule with a `_log` suffix on the name counts the request but does not block it.
  If `enforce` raises an error, the error is tracked and the `:log` rule applies.

The `enforce` lambda receives the `scope:` hash that the caller passes, so you can use any
characteristic value in the scope as the feature flag actor.
Use a characteristic that every caller passes. When the value is `nil`, the flag is checked
without an actor, so an actor list or a percentage-of-actors rollout does not apply to that call.
Use a literal feature flag name in the lambda. The `Gitlab/FeatureFlagKeyDynamic` cop rejects
a name built at runtime.

To roll out the key:

1. Add the key with `staged_rule`, and add the feature flag with `default_enabled: false`.
1. While the flag is disabled, monitor the requests that the key would block:
   - The `gitlab_labkit_rate_limiter_rule_evaluations_total` metric with the `_log` rule name
     and `result="log"`.
   - The `rate_limit_state` field on the request or Sidekiq job log line. It carries
     `applimiter_<key>:<rule>_log:log` when the request was over the limit, and `:allow` when
     it was not. The `meta` fields of the same line say who made the request.
1. Enable the feature flag to enforce the limit. Disable the flag to return to log mode.
1. After the rollout, replace `staged_rule` with `Labkit::RateLimit::Rule.new` and `action: :limit`,
   and remove the feature flag.

Only a staged key adds to `rate_limit_state`, one entry per check and none for a peek, the same way
the request rate limits record their `:log` rules. There is no separate log line.

The `_log` rule and the `:limit` rule use separate Redis counters.
When you enable the flag, the `:limit` rule starts counting from zero.
The `:limit` rule keeps its name after the cleanup, so the `:limit` rule counter is not reset again.

Use `staged_rule` only for a new key.
Instances where the flag is disabled, such as GitLab Self-Managed instances, do not
enforce the limit until you remove the flag.

## Rate limiting architecture

For the design of LabKit rate limiting and proposed changes, see
[Unified rate limiting architecture](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/unified_rate_limiting/).

---
stage: Data Access
group: Database
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Query count limits
---

Each controller, API endpoint and Sidekiq worker is allowed to execute up to
100 SQL queries.
If more than 100 SQL queries are executed, this is a
[performance problem](../performance.md) that should be fixed.

## Solving failing tests

In test environments, we raise an error when this threshold is exceeded.

When a test fails because it executes more than 100 SQL queries there are two
solutions to this problem:

- Reduce the number of SQL queries that are executed.
- Temporarily disable query limiting for the controller or API endpoint.

You should only resort to disabling query limits when an existing controller or endpoint
is to blame as in this case reducing the number of SQL queries can take a lot of
effort. Newly added controllers and endpoints are not allowed to execute more
than 100 SQL queries and no exceptions are made for this rule.

## Pipeline stability

If specs start getting a query limit error in default branch pipelines, follow the [instruction](#disable-query-limiting) to disable the query limit.
Disabling the limit should always associate and prioritize an issue, so the excessive amount of queries can be investigated.

## Disable query limiting

In the event that you have to disable query limits for a controller, you must first
create an issue. This issue should (preferably in the title) mention the
controller or endpoint and include the appropriate labels (`database`,
`performance`, and at least a team specific label such as `Discussion`).

Since [GitLab 17.2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/157016),
`QueryLimiting.disable` must set a new threshold (not unlimited).

After the issue has been created, you can disable query limits on the code in question. For
Rails controllers, it's best to create a `before_action` hook that runs as early
as possible. The called method in turn should call
`Gitlab::QueryLimiting.disable!('issue URL here')`. For example:

```ruby
class MyController < ApplicationController
  before_action :disable_query_limiting, only: [:show]

  def index
    # ...
  end

  def show
    # ...
  end

  def disable_query_limiting
    Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/...', new_threshold: 200)
  end
end
```

By using a `before_action` you don't have to modify the controller method in
question, reducing the likelihood of merge conflicts.

For Grape API endpoints, there unfortunately is not a reliable way of running a
hook before a specific endpoint. This means that you have to add the allowlist
call directly into the endpoint like so:

```ruby
get '/projects/:id/foo' do
  Gitlab::QueryLimiting.disable!('...', new_threshold: 200)

  # ...
end
```

For Sidekiq workers, you will need to add the allowlist directly as well:

```ruby
def perform(args)
  Gitlab::QueryLimiting.disable!('...', new_threshold: 200)

  # ...
end
```

## Exclude amortized queries from query counts

Some queries run only occasionally, for example once per user per day,
and are counted against whichever request triggers them.
To keep these queries out of the request limit and out of `ActiveRecord::QueryRecorder` counts in specs,
wrap them in `Gitlab::QueryLimiting.without_counting`:

```ruby
Gitlab::QueryLimiting.without_counting do
  user.update_attribute(:last_activity_on, Date.today)
end
```

The block applies to the current thread only.
Use `without_counting` only for queries that are amortized in regular usage.
Do not use `without_counting` to hide N+1 queries.
To let a request run more queries, [disable query limiting](#disable-query-limiting) instead.

## Disable query limiting in spec support code

`Gitlab::QueryLimiting.with_suppressed_globally` turns off query limiting for every thread in the process.
Use this method only in spec support code where the application server handles requests on other threads,
for example in `spec/support/capybara.rb`.
The method does not affect `ActiveRecord::QueryRecorder`.

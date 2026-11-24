---
stage: none
group: unassigned
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Sidekiq worker attributes
---

Worker classes can define certain attributes to control their behavior and add metadata.

Child classes inheriting from other workers also inherit these attributes, so you only
have to redefine them if you want to override their values.

## Job urgency

Jobs can have an `urgency` attribute set, which can be `:high`,
`:low`, or `:throttled`. These have the below targets:

| **Urgency**      | **Queue Scheduling Target**   | **Execution Latency Requirement**    |
|---------------   | ----------------------------- | ------------------------------------ |
| `:high`          | 10 seconds                    | 10 seconds                           |
| `:low` (default) | 1 minute                      | 5 minutes                            |
| `:throttled`     | None                          | 5 minutes                            |

To set a job's urgency, use the `urgency` class method:

```ruby
class HighUrgencyWorker
  include ApplicationWorker

  urgency :high

  # ...
end
```

### Latency sensitive jobs

If a large number of background jobs get scheduled at once, queueing of jobs may
occur while jobs wait for a worker node to be become available. This is standard
and gives the system resilience by allowing it to gracefully handle spikes in
traffic. Some jobs, however, are more sensitive to latency than others.

In general, latency-sensitive jobs perform operations that a user could
reasonably expect to happen synchronously, rather than asynchronously in a
background worker. A common example is a write following an action. Examples of
these jobs include:

1. A job which updates a merge request following a push to a branch.
1. A job which invalidates a cache of known branches for a project after a push
   to the branch.
1. A job which recalculates the groups and projects a user can see after a
   change in permissions.
1. A job which updates the status of a CI pipeline after a state change to a job
   in the pipeline.

When these jobs are delayed, the user may perceive the delay as a bug: for
example, they may push a branch and then attempt to create a merge request for
that branch, but be told in the UI that the branch does not exist. We deem these
jobs to be `urgency :high`.

Extra effort is made to ensure that these jobs are started within a very short
period of time after being scheduled. However, to ensure throughput,
these jobs also have very strict execution duration requirements:

1. The median job execution time should be less than 1 second.
1. 99% of jobs should complete within 10 seconds.

If a worker cannot meet these expectations, then it cannot be treated as a
`urgency :high` worker: consider redesigning the worker, or splitting the
work between two different workers, one with `urgency :high` code that
executes quickly, and the other with `urgency :low`, which has no
execution latency requirements (but also has lower scheduling targets).

### Changing a queue's urgency

On GitLab.com, we run Sidekiq in several
[shards](https://dashboards.gitlab.net/d/sidekiq-shard-detail/sidekiq-shard-detail),
each of which represents a particular type of workload.

When changing a queue's urgency, or adding a new queue, we need to take
into account the expected workload on the new shard. If we're
changing an existing queue, there is also an effect on the old shard,
but that always reduces work.

To do this, we want to calculate the expected increase in total execution time
and RPS (throughput) for the new shard. We can get these values from:

- The [Queue Detail dashboard](https://dashboards.gitlab.net/d/sidekiq-queue-detail/sidekiq-queue-detail)
  has values for the queue itself. For a new queue, we can look for
  queues that have similar patterns or are scheduled in similar
  circumstances.
- The [Shard Detail dashboard](https://dashboards.gitlab.net/d/sidekiq-shard-detail/sidekiq-shard-detail)
  has Total Execution Time and Throughput (RPS). The Shard Utilization
  panel displays if there is currently any excess capacity for this
  shard.

We can then calculate the RPS * average runtime (estimated for new jobs)
for the queue we're changing to see what the relative increase in RPS and
execution time we expect for the new shard:

```ruby
new_queue_consumption = queue_rps * queue_duration_avg
shard_consumption = shard_rps * shard_duration_avg

(new_queue_consumption / shard_consumption) * 100
```

If we expect an increase of less than 5%, then no further action is needed.

Otherwise, ping `@gitlab-com/gl-infra/data-access/durability` on the merge request and ask
for a review.

## Jobs with External Dependencies

Most background jobs in the GitLab application communicate with other GitLab
services. For example, PostgreSQL, Redis, Gitaly, and Object Storage. These are considered
to be "internal" dependencies for a job.

However, some jobs are dependent on external services to complete
successfully. Some examples include:

1. Jobs which call web-hooks configured by a user.
1. Jobs which deploy an application to a Kubernetes cluster configured by a user.

These jobs have "external dependencies". This is important for the operation of
the background processing cluster in several ways:

1. Most external dependencies (such as web-hooks) do not provide SLOs, and
   therefore we cannot guarantee the execution latencies on these jobs. Since we
   cannot guarantee execution latency, we cannot ensure throughput and
   therefore, in high-traffic environments, we need to ensure that jobs with
   external dependencies are separated from high urgency jobs, to ensure
   throughput on those queues.
1. Errors in jobs with external dependencies have higher alerting thresholds as
   there is a likelihood that the cause of the error is external.

```ruby
class ExternalDependencyWorker
  include ApplicationWorker

  # Declares that this worker depends on
  # third-party, external services in order
  # to complete successfully
  worker_has_external_dependencies!

  # ...
end
```

A job cannot be both high urgency and have external dependencies.

## CPU-bound and Memory-bound Workers

Workers that are constrained by CPU or memory resource limitations should be
annotated with the `worker_resource_boundary` method.

Most workers tend to spend most of their time blocked, waiting on network responses
from other services such as Redis, PostgreSQL, and Gitaly. Since Sidekiq is a
multi-threaded environment, these jobs can be scheduled with high concurrency.

Some workers, however, spend large amounts of time _on-CPU_ running logic in
Ruby. Ruby MRI does not support true multi-threading - it relies on the
[GIL](https://thoughtbot.com/blog/untangling-ruby-threads#the-global-interpreter-lock)
to greatly simplify application development by only allowing one section of Ruby
code in a process to run at a time, no matter how many cores the machine
hosting the process has. For IO bound workers, this is not a problem, since most
of the threads are blocked in underlying libraries (which are outside of the
GIL).

If many threads are attempting to run Ruby code simultaneously, this leads
to contention on the GIL which has the effect of slowing down all
processes.

In high-traffic environments, knowing that a worker is CPU-bound allows us to
run it on a different fleet with lower concurrency. This ensures optimal
performance.

Likewise, if a worker uses large amounts of memory, we can run these on a
bespoke low concurrency, high memory fleet.

Memory-bound workers create heavy GC workloads, with pauses of
10-50 ms. This has an impact on the latency requirements for the
worker. For this reason, `memory` bound, `urgency :high` jobs are not
permitted and fail CI. In general, `memory` bound workers are
discouraged, and alternative approaches to processing the work should be
considered.

If a worker needs large amounts of both memory and CPU time, it should
be marked as memory-bound, due to the above restriction on high urgency
memory-bound workers.

## Declaring a Job as CPU-bound

This example shows how to declare a job as being CPU-bound.

```ruby
class CPUIntensiveWorker
  include ApplicationWorker

  # Declares that this worker will perform a lot of
  # calculations on-CPU.
  worker_resource_boundary :cpu

  # ...
end
```

## Determining whether a worker is CPU-bound

We use the following approach to determine whether a worker is CPU-bound:

- In the Sidekiq structured JSON logs, aggregate the worker `duration` and
  `cpu_s` fields.
- `duration` refers to the total job execution duration, in seconds
- `cpu_s` is derived from the
  [`Process::CLOCK_THREAD_CPUTIME_ID`](https://www.rubydoc.info/stdlib/core/Process:clock_gettime)
  counter, and is a measure of time spent by the job on-CPU.
- Divide `cpu_s` by `duration` to get the percentage time spend on-CPU.
- If this ratio exceeds 33%, the worker is considered CPU-bound and should be
  annotated as such.
- These values should not be used over small sample sizes, but
  rather over fairly large aggregates.

## Feature category

All Sidekiq workers must define a known [feature category](../feature_categorization/_index.md#sidekiq-workers).

## Job data consistency strategies

Previously, Sidekiq workers would always send database queries to the primary
database node,
both for reads and writes. This ensured that data integrity
is both guaranteed and immediate, since in a single-node scenario it is impossible to encounter
stale reads even for workers that read their own writes.
If a worker writes to the primary, but reads from a replica, however, the possibility
of reading a stale record is non-zero due to replicas potentially lagging behind the primary.

When the number of jobs that rely on the database increases, ensuring immediate data consistency
can put unsustainable load on the primary database server. We therefore added the ability to use
[Database Load Balancing for Sidekiq workers](../../administration/postgresql/database_load_balancing.md).
By configuring a worker's `data_consistency` field, we can then allow the scheduler to target read replicas
under several strategies outlined below.

### Trading immediacy for reduced primary load

We require Sidekiq workers to make an explicit decision around whether they need to use the
primary database node for all reads and writes, or whether reads can be served from replicas. This is
enforced by a RuboCop rule, which ensures that the `data_consistency` field is set.

Before `data_consistency` was introduced, the default behavior mimicked that of `:always`. Since jobs are
now enqueued along with the current database LSN, the replica (for `:sticky` or `:delayed`) is guaranteed
to be caught up to that point, or the job will be retried, or use the primary. This means that the data
will be consistent at least to the point at which the job was enqueued.

The table below shows the `data_consistency` attribute and its values, ordered by the degree to which
they prefer read replicas and wait for replicas to catch up:

| **Data consistency**  | **Description**  | **Guideline** |
|--------------|-----------------------------|----------|
| `:always`    | The job is required to use the primary database for all queries. | Strongly discouraged. Only needed for jobs that encounter edge cases around primary stickiness. |
| `:sticky`    | The job prefers replicas, but switches to the primary for writes or when encountering replication lag. | This is the preferred option. It should be used for jobs that need to be executed as fast as possible. Replicas are guaranteed to be caught up to the point at which the job was enqueued in Sidekiq. |
| `:delayed`   | The job prefers replicas, but switches to the primary for writes. When encountering replication lag before the job starts, the job is retried once. If the replica is still not up to date on the next retry, it switches to the primary. | It should be used for jobs where delaying execution further typically does not matter, such as cache expiration or web hooks execution. It should not be used for jobs where retry is disabled, such as cron jobs. |

In all cases workers read either from a replica that is fully caught up,
or from the primary node, so data consistency is always ensured.

To set a data consistency for a worker, use the `data_consistency` class method:

```ruby
class DelayedWorker
  include ApplicationWorker

  data_consistency :delayed

  # ...
end
```

### Overriding data consistency for a decomposed database

GitLab uses multiple decomposed databases. Sidekiq workers usage of the respective databases may be skewed towards
a particular database. For example, `PipelineProcessWorker` has a higher write traffic to the `ci` database compared to the
`main` database. In the event of edge cases around primary stickiness, having separate data consistency defined for each
database allows the worker to more efficiently use read replicas.

If the `overrides` keyword argument is set, the `Gitlab::Database::LoadBalancing::SidekiqServerMiddleware` loads the load
balancing strategy using the data consistency which most prefers the read replicas.
The order of preference in increasing preference is: `:always`, `:sticky`, then `:delayed`.

The overrides only apply if the GitLab instance is using multiple databases or `Gitlab::Database.database_mode == Gitlab::Database::MODE_MULTIPLE_DATABASES`.

To set a data consistency for a worker, use the `data_consistency` class method with the `overrides` keyword argument:

```ruby
class MultipleDataConsistencyWorker
  include ApplicationWorker

  data_consistency :always, overrides: { ci: :sticky }

  # ...
end
```

### `feature_flag` property

The `feature_flag` property allows you to toggle a job's `data_consistency`,
which permits you to safely toggle load balancing capabilities for a specific job.
When `feature_flag` is disabled, the job defaults to `:always`, which means that the job always uses the primary database.

The `feature_flag` property does not allow the use of
[feature gates based on actors](../feature_flags/_index.md).
This means that the feature flag cannot be toggled only for particular
projects, groups, or users, but instead, you can safely use [percentage of time rollout](../feature_flags/_index.md).
Since we check the feature flag on both Sidekiq client and server, rolling out a 10% of the time,
likely results in 1% (`0.1` `[from client]*0.1` `[from server]`) of effective jobs using replicas.

Example:

```ruby
class DelayedWorker
  include ApplicationWorker

  data_consistency :delayed, feature_flag: :load_balancing_for_delayed_worker

  # ...
end
```

When using the `feature_flag` property with `overrides`, the jobs defaults to `always` for all database connections.
When the feature flag is enabled, the configured data consistency is then applied to each database independently.
For the below example, when the flag is enabled, the `main` database connections will use the `:always` data consistency while
`ci` database connections will use `:sticky` data consistency.

```ruby
class DelayedWorker
  include ApplicationWorker

  data_consistency :always, overrides: { ci: :sticky }, feature_flag: :load_balancing_for_delayed_worker

  # ...
end
```

### Data consistency with idempotent jobs

For [idempotent jobs](idempotent_jobs.md) that declare either `:sticky` or `:delayed` data consistency, we are
[preserving the latest WAL location](idempotent_jobs.md#preserve-the-latest-wal-location-for-idempotent-jobs) while deduplicating,
ensuring that we read from the replica that is fully caught up.

## Job pause control

With the `pause_control` property, you can conditionally pause job processing. If the strategy is active, the job
is stored in a separate `ZSET` and re-enqueued when the strategy becomes inactive. `PauseControl::ResumeWorker` is a cron
worker that checks if any paused jobs must be restarted.

To use `pause_control`, you can:

- Use one of the strategies defined in `lib/gitlab/sidekiq_middleware/pause_control/strategies/`.
- Define a custom strategy in `lib/gitlab/sidekiq_middleware/pause_control/strategies/` and add the strategy to `lib/gitlab/sidekiq_middleware/pause_control.rb`.

For example:

```ruby
module Gitlab
  module SidekiqMiddleware
    module PauseControl
      module Strategies
        class CustomStrategy < Base
          def should_pause?
            ApplicationSetting.current.elasticsearch_pause_indexing?
          end
        end
      end
    end
  end
end
```

```ruby
class PausedWorker
  include ApplicationWorker

  pause_control :custom_strategy

  # ...
end
```

> [!warning]
> In case you want to remove the middleware for a worker, set the strategy to `:deprecated` to disable it and wait until
> a required stop before removing it completely. That ensures that all paused jobs are resumed correctly.

## Concurrency limit

With the `concurrency_limit` property, you can limit the worker's concurrency. It will put the jobs that are over this limit in
a separate `LIST` and re-enqueued when it falls under the limit. `ConcurrencyLimit::ResumeWorker` is a cron
worker that checks if any throttled jobs should be re-enqueued.

> [!note]
> The `ops` feature flag `concurrency_limit_eager_resume_processing` can be enabled to increase the jobs resumption
> throughput of `ConcurrencyLimit::ResumeWorker`. However, this comes with a risk whereby resumed jobs could surpass
> the concurrency limit when the Sidekiq queue is also backlogged.
> See [issue 579350](https://gitlab.com/gitlab-org/gitlab/-/issues/579350) for more details.

The first job that crosses the defined concurrency limit initiates the throttling process for all other jobs of this class.
Until this happens, jobs are scheduled and executed as usual.

When the throttling starts, newly scheduled and executed jobs will be added to the end of the `LIST` to ensure that
the execution order is preserved. As soon as the `LIST` is empty again, the throttling process ends.

Prometheus metrics are exposed to monitor workers using concurrency limit middleware:

- `sidekiq_concurrency_limit_deferred_jobs_total`
- `sidekiq_concurrency_limit_queue_jobs`
- `sidekiq_concurrency_limit_queue_jobs_total`
- `sidekiq_concurrency_limit_max_concurrent_jobs`
- `sidekiq_concurrency_limit_current_concurrent_jobs_total`

> [!warning]
> If there is a sustained workload over the limit, the `LIST` is going to grow until the limit is disabled or
> the workload drops under the limit.

You should use a lambda to define the limit. If it returns `nil` or `0`, the limit won't be applied.
Negative numbers pause the execution.

```ruby
class LimitedWorker
  include ApplicationWorker

  concurrency_limit -> { 60 }

  # ...
end
```

```ruby
class LimitedWorker
  include ApplicationWorker

  concurrency_limit -> { ApplicationSetting.current.elasticsearch_concurrent_sidekiq_jobs }

  # ...
end
```

### Default Concurrency Limit

On GitLab.com, we have applied a [default concurrency limit for all workers](https://gitlab.com/gitlab-com/gl-infra/tenant-scale/tenant-services/team/-/issues/215)
calculated based on the Sidekiq shard's capacity (`threads * maxReplicas * maxPercentage`).

- `threads`: Number of `concurrency` configured for the shard. [Example for `catchall` shard](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com/-/blob/d322295ee8c4aa1681d92695678af232c4135cfb/releases/gitlab/values/gprd.yaml.gotmpl#L706).
- `maxReplicas`: Number of max replicas configured for the shard. [Example for `catchall` shard](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com/-/blob/d322295ee8c4aa1681d92695678af232c4135cfb/releases/gitlab/values/gprd.yaml.gotmpl#L709-710).
- `maxPercentage`: A percentage based on the worker's urgency. The [configuration](https://gitlab.com/gitlab-org/gitlab/blob/69deb38d99685f72d7e8494fe503d80b93b650ed/app/workers/concerns/worker_attributes.rb#L44-48).

> [!note]
> This only applies if the static `concurrency_limit` attribute has not been set.

To override the default `maxPercentage`, you can define the `max_concurrency_limit_percentage` attribute:

```ruby
class LimitedWorker
  include ApplicationWorker

  max_concurrency_limit_percentage 0.5 # This will use 50% of the shard's maximum capacity.

  # ...
end
```

### Enqueue checks with shard-derived defaults

Web and API processes cannot calculate a default from the capacity of the destination Sidekiq shard.
Enable the worker-type flag `sidekiq_concurrency_limit_enqueue_<WorkerName>` to use a published
default for enqueue checks.
The flag is disabled by default and must be enabled as a boolean, not a percentage rollout.

The Sidekiq concurrency-limit sampler publishes defaults only for queues and Redis queue shards
served by its process, with an expiry equal to the sampler lease plus one sampling interval (330 seconds).
Enqueue processes cache each published default, including missing values, for one second.
Enqueue checks read defaults and effective limits only while the worker has a deferred backlog.
Explicit worker limits, pauses, operator overrides, and adaptive limits retain their precedence.
Overrides and execution counts are not cached by this mechanism.

If a publication is missing or expires, limit resolution falls back to the existing local default
and any live override or adaptive limit.
Failed publication reads are reported and cached as missing for one second.
If the live override or adaptive-limit read fails, enqueue checks report the Redis error and use the local default.
Execution-time Redis error handling is unchanged.
Server-side checks remain authoritative because capacity can change after enqueue.
This change does not reserve a slot when a job is enqueued.

Disable `sidekiq_concurrency_limit_enqueue_<WorkerName>` to restore the previous enqueue path.
Jobs already in deferred storage continue through the existing resumer.

### Concurrency limit per top-level group or user

> [!warning]
> The `concurrency_limit_scope` attribute is an experiment. Adopt it behind a feature flag of
> the worker, set with `enabled:`, so you can turn it off. Until
> [issue 637499](https://gitlab.com/gitlab-org/gitlab/-/work_items/637499) is resolved,
> high-volume workers should not adopt it.

By default, all jobs of a worker share its concurrency limit, so one top-level group that enqueues
a burst of jobs can delay every other group's jobs. To cap each top-level group or user at a share
of the worker's limit, define the `concurrency_limit_scope` attribute:

```ruby
class LimitedWorker
  include ApplicationWorker

  # Each top-level group can use at most 20% of the worker's concurrency limit.
  concurrency_limit_scope(:root_namespace, max_percentage: 0.2,
    enabled: -> { Feature.enabled?(:limited_worker_scoped_concurrency_limit, :instance) })

  def perform(merge_request_id)
    # ...
  end
end
```

- `enabled:` is optional. It is a lambda that turns the scope on for this worker, usually a feature
  flag of the worker, so each worker can roll out on its own. Check the flag against `:instance`
  only, because enqueuing, running, and resuming a job must agree on whether the worker is scoped.
- The first argument is the scope: `:root_namespace` (the top-level group) or `:user`.
- Set `max_percentage:` (a share of the worker's limit), `limit:` (a lambda that returns a number of
  jobs), or both. With both, the lower one applies. A `limit` of `0` or less is ignored, so a worker
  with only `limit:` stays unscoped while it returns `0`.
- The job counts against the top-level group (`meta.root_namespace`) or user (`meta.gl_user_id`)
  in its [application context](logging.md), with no database lookup. This context comes from the
  code that enqueued the job, so schedule jobs with the context of the group or user they belong to,
  for example with `bulk_perform_async_with_contexts`.
- A job whose context has no top-level group or user is bound only by the worker's limit. The
  `sidekiq_concurrency_limit_scope_unattributed_jobs_total` metric counts these jobs, to show how
  much of the worker's traffic the scope covers.
- The worker's limit still applies to all scopes together.
- Deferred jobs wait in a queue per scope, so the backlog of one scope does not delay the jobs
  of the others.

The scope applies only while all of these are true:

- The `sidekiq_concurrency_limit_scope` feature flag is enabled. It is disabled by default.
- The `disable_sidekiq_concurrency_limit_scope_<WorkerName>` feature flag is not enabled. Enable it to
  turn off the scope for one worker, for example during an incident, while the worker's own
  concurrency limit stays on.
- The worker's `enabled:` lambda, if any, returns `true`.

When the scope is turned off, jobs already deferred in its queues are still resumed.

In specs, a feature flag you did not stub is enabled, so the
`disable_sidekiq_concurrency_limit_scope_<WorkerName>` flag turns the scope off. In the specs of a
scoped worker, set `stub_feature_flags(disable_sidekiq_concurrency_limit_scope_<WorkerName>: false)`.

### Run code when a job is deferred or resumed

A worker with a concurrency limit can define `self.on_concurrency_limit_deferred(args)` and
`self.on_concurrency_limit_resumed(args)`. They receive the job arguments, and run when a job is
deferred and when it is resumed. Use them, for example, to refresh state the job depends on while it
waits. Errors in them are tracked, not raised.

- Hooks run inline, while the job is enqueued or resumed, so keep them cheap.
- A hook can run more than once for the same job, for example when a resume is retried or a job is
  deferred again. Make hooks idempotent.
- Hooks do not run while a job waits. State with a TTL can expire if a job waits longer than the TTL.

### Running new jobs while deferred jobs wait

By default, a non-empty `LIST` defers every new job of the worker, even when the worker is far below its
limit, so that jobs run in the order they were scheduled. A brief spike to the limit therefore starts a
backlog that drains only as fast as `ConcurrencyLimit::ResumeWorker` resubmits jobs.

For a worker whose jobs do not depend on each other's order, enable the `worker` type feature flag
`sidekiq_concurrency_limit_use_free_slots_<WorkerName>`. It is disabled by default and has no YAML
definition. While it is enabled:

- A new job runs whenever the worker is below its limit, even if the `LIST` is not empty. It is deferred
  only while the worker is at its limit.
- Resumed jobs reserve their slot when `ConcurrencyLimit::ResumeWorker` picks them, so new jobs cannot
  take the slots counted for them.
- Once the oldest job in the `LIST` has waited 5 minutes, new jobs leave 10% of the limit (at least one
  slot) free for resumed jobs, so the `LIST` keeps draining under sustained load.
- When `ConcurrencyLimit::ResumeWorker` finds the worker at its limit, it reschedules itself for one second
  later instead of waiting for its next cron run.
  Without the flag, a run that finds the worker at its limit ends without rescheduling.

The limit stays a hard bound. A new job can run before an older deferred job of the same worker, so
confirm with the worker's owning group that its jobs are order independent before enabling the flag.
While the worker's `concurrency_limit_scope` is on, the flag has no effect, because its jobs already wait
only behind their own scope. With the scope turned off, the flag applies as it does to an unscoped worker.

In specs, a feature flag you did not stub is enabled. To test the default ordering behavior of a
worker, set `stub_feature_flags(sidekiq_concurrency_limit_use_free_slots_<WorkerName>: false)`.

## Skip execution of workers in Geo secondary

On Geo secondary sites, database writes are disabled.
You must skip execution of workers that attempt database writes from Geo secondary sites,
if those workers get enqueued on Geo secondary sites.
Conveniently, most workers do not get enqueued on Geo secondary sites, because
[most non-GET HTTP requests get proxied to the Geo primary site](https://gitlab.com/gitlab-org/gitlab/-/blob/v16.8.0-ee/workhorse/internal/upstream/routes.go#L382-L431),
and because Geo secondary sites
[disable most Sidekiq-Cron jobs](https://gitlab.com/gitlab-org/gitlab/-/blob/v16.8.0-ee/ee/lib/gitlab/geo/cron_manager.rb#L6-L26).
Ask a Geo engineer if you are unsure.
To skip execution, prepend the `::Geo::SkipSecondary` module to the worker class.

```ruby
class DummyWorker
  include ApplicationWorker
  prepend ::Geo::SkipSecondary

 # ...
end
```

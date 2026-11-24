---
stage: Platforms
group: Global Search
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Zoekt tasks SLIs (service level indicators)
---

The Zoekt tasks SLIs track the performance and reliability of asynchronous indexing tasks
for Zoekt code search.

## Metrics

The following metrics are emitted for Zoekt task processing:

### Request rate

- `gitlab_sli_search_zoekt_tasks_requests_total`: Counter that tracks the rate of tasks
  being added to the Zoekt indexing queue. This metric increments when tasks are created
  via `Search::Zoekt::Repository#create_bulk_tasks`.

### Error rate

- `gitlab_sli_search_zoekt_tasks_total`: Counter for total number of task completion attempts.
- `gitlab_sli_search_zoekt_tasks_error_total`: Counter for tasks that reached final failure state
  (after retries exhausted). This metric only increments when a task transitions to the `:failed`
  state, not during intermediate retries.

### Apdex (Application Performance Index)

The Apdex SLI measures task completion performance with a 2-hour (7200 second)
threshold, defined as `APDEX_THRESHOLD_S` in
`ee/lib/gitlab/metrics/zoekt_tasks_slis.rb`.

The following metrics track Apdex:

- `gitlab_sli_search_zoekt_tasks_apdex_total`: Counter for total number of completed tasks.
- `gitlab_sli_search_zoekt_tasks_apdex_success_total`: Counter for tasks that completed
  within the threshold.

### Task duration

The Apdex records only whether a task beat its threshold.
`gitlab_search_zoekt_task_duration_seconds` is a histogram of the same
duration, observed in the same call, so duration quantiles are computable.

Buckets are `1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600` seconds.
The exact `60` edge answers a 60-second objective with a bucket read, not an interpolated quantile.
`7200` is an exact edge too, so the Apdex ratio is re-derivable from the bucket series.
Match it with `le=~"7200(\\.0+)?"`, which covers both stored forms of the `le` label.

The duration is `Time.current - task.perform_at`, so it covers queue wait and
execution together. The next section splits that interval into its two parts.

Each sample also logs a `Zoekt task Apdex SLI` line to `Gitlab::AppJsonLogger`
with `duration_s`, `target_s`, `success`, `zoekt_node`, and `task_type`, so
percentiles are available from logs as well as from the histogram. When the
split below was recorded, that line also carries `queue_wait_s` and
`processing_s`. Both fields are absent when the split was skipped, so a line
with `duration_s` and no `queue_wait_s` is a skip and not a zero.

### Queue wait and processing time

The Apdex reduces a duration to a boolean, so it cannot answer how long tasks actually
wait. Two histograms decompose the same interval into the time a due task spent queued
and the time it spent being worked:

- `gitlab_search_zoekt_task_queue_duration_seconds`: Time from a task becoming due
  (`perform_at`) to a node claiming it. Bucket edges are
  `1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 21600` seconds, plus `+Inf`.
  The `60` edge is exact, so the fraction of tasks that waited less than a minute is
  read off that bucket series directly, rather than interpolated. See
  [Queue-wait percentiles](#queue-wait-percentiles-and-the-fraction-under-60-seconds)
  for how the `le` label is actually stored and matched.
- `gitlab_search_zoekt_task_processing_duration_seconds`: Time from the claim to the
  completion callback being handled. Bucket edges are
  `0.1, 0.5, 1, 5, 10, 30, 60, 300, 900, 1800, 3600` seconds, plus `+Inf`.

For any task producing both, the two values sum to the Apdex's measured duration.

The claim instant is not stored.
The code derives it by subtracting the claim offset from `claimed_until`.
The offset is `zoekt_indexing_timeout` plus a one-hour grace period.
No observation is recorded when the derivation is unavailable or implausible.
`claimed_until` is `NULL` when the row predates the column or was reset to `pending` for a retry.
A derived instant outside `perform_at..now` can only come from the offset changing mid-flight.
In both cases the Apdex sample is still recorded.

### Negative durations

A retry rewrites `perform_at` to a future time.
A success callback that arrives before that time computes a negative interval.
All three histogram observations are floored at 0.
A negative observation would decrement the `_sum` counter and make the mean unusable.
The Apdex and the log line keep the raw value, so the anomaly stays visible in the logs.

## Labels

All metrics include the following labels for detailed analysis:

- `zoekt_node`: The Zoekt node identifier handling the task (from `zoekt_node_id`)
- `task_type`: The operation type, such as:
  - `index_repo`: Full repository indexing
  - `delete_repo`: Repository deletion from index
  - Other task-specific operations

## Example Prometheus queries

### Overall task success rate

```promql
rate(gitlab_sli_search_zoekt_tasks_apdex_success_total[5m])
/
rate(gitlab_sli_search_zoekt_tasks_apdex_total[5m])
```

### Error rate by node

```promql
sum by (zoekt_node) (
  rate(gitlab_sli_search_zoekt_tasks_error_total[5m])
)
/
sum by (zoekt_node) (
  rate(gitlab_sli_search_zoekt_tasks_total[5m])
)
```

### Task duration percentiles

```promql
histogram_quantile(0.99,
  sum by (le, zoekt_node, task_type) (
    rate(gitlab_search_zoekt_task_duration_seconds_bucket[5m])
  )
)
```

### Fraction of tasks completing within 60 seconds

How Prometheus canonicalizes an integer `le` label on ingest depends on the
scrape pipeline, so a bare `le="60"` or `le="60.0"` is not portable across
environments. Use `le=~"60(\\.0+)?"`, which matches both forms.

```promql
sum(rate(gitlab_search_zoekt_task_duration_seconds_bucket{le=~"60(\\.0+)?"}[5m]))
/
sum(rate(gitlab_search_zoekt_task_duration_seconds_count[5m]))
```

### Task throughput by type

```promql
sum by (task_type) (
  rate(gitlab_sli_search_zoekt_tasks_requests_total[5m])
)
```

### Slow tasks (exceeding Apdex threshold)

```promql
rate(gitlab_sli_search_zoekt_tasks_apdex_total[5m])
-
rate(gitlab_sli_search_zoekt_tasks_apdex_success_total[5m])
```

### Per-node, per-type error rate

```promql
sum by (zoekt_node, task_type) (
  rate(gitlab_sli_search_zoekt_tasks_error_total[5m])
)
```

### Queue-wait percentiles and the fraction under 60 seconds

One query answers the 60-second objective and the shape of the distribution behind it:

```promql
label_replace(histogram_quantile(0.5, sum by (le) (rate(gitlab_search_zoekt_task_queue_duration_seconds_bucket[1h]))), "stat", "p50_seconds", "", "")
or
label_replace(histogram_quantile(0.9, sum by (le) (rate(gitlab_search_zoekt_task_queue_duration_seconds_bucket[1h]))), "stat", "p90_seconds", "", "")
or
label_replace(histogram_quantile(0.99, sum by (le) (rate(gitlab_search_zoekt_task_queue_duration_seconds_bucket[1h]))), "stat", "p99_seconds", "", "")
or
label_replace(
  sum(rate(gitlab_search_zoekt_task_queue_duration_seconds_bucket{le=~"60(\\.0+)?"}[1h]))
  / sum(rate(gitlab_search_zoekt_task_queue_duration_seconds_count[1h])),
  "stat", "fraction_under_60s", "", ""
)
```

The last term is exact rather than interpolated because `60` is a declared bucket edge.
Match the term with the regular expression rather than a bare `le="60"` or `le="60.0"`
because the stored form of the label can differ between environments.
On GitLab.com, the label is stored as `le="60"`, so `le="60.0"` matches nothing.

## Implementation details

The SLI is defined in `Gitlab::Metrics::ZoektTasksSlis` and instrumented at key
points in the task lifecycle:

- **Request rate**: Incremented when tasks are created in `Search::Zoekt::Repository#create_bulk_tasks`
- **Error rate**: Incremented when tasks reach final failure in `Search::Zoekt::CallbackService#process_failure`
- **Apdex**: Recorded when tasks complete successfully in `Search::Zoekt::CallbackService#process_zoekt_success`
- **Queue wait and processing time**: Observed in the same call that records the Apdex,
  from the claim instant derived off `Search::Zoekt::Taskable#plausible_claimed_at`

For more information about Application SLIs, see the [Application SLI framework documentation](_index.md).

# Application SLIs

This module provides [Application Service Level Indicators(SLIs)](https://docs.gitlab.com/development/application_slis/)
for monitoring and observability. It allows defining SLIs directly in Ruby code, keeping the definition of operations and their success close to the implementation.

Two SLI types are available:

- **`Labkit::ApplicationSli::Apdex`** - Measures the performance of successful operations using a success rate.
- **`Labkit::ApplicationSli::ErrorRate`** - Measures the rate of unsuccessful operations using an error rate.

## Defining a new SLI

When you define an SLI, two [Prometheus counters](https://prometheus.io/docs/concepts/metric_types/#counter) are emitted. Both contain a total operation count, and a numerator counter for the success or error rate.

`Labkit::ApplicationSli::Apdex` defines:

- `gitlab_sli_<name>_apdex_total` - total number of measurements
- `gitlab_sli_<name>_apdex_success_total` - number of successful measurements

`Labkit::ApplicationSli::ErrorRate` defines:

- `gitlab_sli_<name>_total` - total number of measurements
- `gitlab_sli_<name>_error_total` - number of error measurements

## Initializing an SLI

Before the first Prometheus scrape, initialize the SLI with all possible label combinations to [avoid missing metrics](https://prometheus.io/docs/practices/instrumentation/#avoid-missing-metrics):

```ruby
Labkit::ApplicationSli::Apdex.initialize_sli(:received_email, [
  {
    feature_category: :team_planning,
    email_type: :create_issue
  },
  {
    feature_category: :service_desk,
    email_type: :service_desk
  }
])
```

## Tracking operations

Increment the SLI counters using the `#increment` method with the appropriate labels.

For `Apdex`, pass `success:` to indicate whether the operation met the performance target:

```ruby
Labkit::ApplicationSli::Apdex[:received_email].increment(
  labels: {
    feature_category: :service_desk,
    email_type: :service_desk
  },
  success: issue_created?
)
```

For `ErrorRate`, pass `error:` to indicate whether the operation failed:

```ruby
Labkit::ApplicationSli::ErrorRate[:merge].increment(
  labels: {
    merge_type: :fast_forward
  },
  error: !merge_success?
)
```

When `success:` (or `error:`) is truthy, both the total and numerator counters are incremented. When falsy, only the total counter is incremented.

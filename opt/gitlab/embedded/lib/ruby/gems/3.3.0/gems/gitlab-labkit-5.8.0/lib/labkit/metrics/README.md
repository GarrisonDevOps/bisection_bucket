# Labkit::Metrics

## Usage

```ruby
# create a new counter metric and returns it
http_requests = Labkit::Metrics::Client.counter(:http_requests, 'A counter of HTTP requests made')
# start using the counter
http_requests.increment

# resets the registry and reinitializes all metrics files
Labkit::Metrics::Client.reset!

# retrieves the metric (be it a counter, gauge, histogram, summary)
http_requests = Labkit::Metrics::Client.get(:http_requests)
```

### Counter

```ruby
counter = Labkit::Metrics::Client.counter(:service_requests_total, '...')

# increment the counter for a given label set
counter.increment({ service: 'foo' })

# increment by a given value
counter.increment({ service: 'bar' }, 5)

# get current value for a given label set
counter.get({ service: 'bar' })
# => 5
```

### Gauge

```ruby
gauge = Labkit::Metrics::Client.gauge(:room_temperature_celsius, '...')

# set a value
gauge.set({ room: 'kitchen' }, 21.534)

# retrieve the current value for a given label set
gauge.get({ room: 'kitchen' })
# => 21.534
```

### Histogram

```ruby
histogram = Labkit::Metrics::Client.histogram(:service_latency_seconds, '...')

# record a value
histogram.observe({ service: 'users' }, Benchmark.realtime { service.call(arg) })

# retrieve the current bucket values
histogram.get({ service: 'users' })
# => { 0.005 => 3, 0.01 => 15, 0.025 => 18, ..., 2.5 => 42, 5 => 42, 10 => 42 }
```

### Summary

```ruby
summary = Labkit::Metrics::Client.summary(:service_latency_seconds, '...')

# record a value
summary.observe({ service: 'database' }, Benchmark.realtime { service.call() })

# retrieve the current quantile values
summary.get({ service: 'database' })
# => { 0.5 => 0.1233122, 0.9 => 3.4323, 0.99 => 5.3428231 }
```

## Rack middleware

```ruby
# config.ru

require 'rack'
require 'labkit/metrics/rack_exporter'

use Labkit::Metrics::RackExporter

run ->(env) { [200, {'Content-Type' => 'text/html'}, ['OK']] }
```

## Configuration

```ruby
# config/initializers/metrics.rb

Labkit::Metrics::Client.reinitialize_on_pid_change(force: true)

Labkit::Metrics::Client.configure do |config|
  config.logger = Gitlab::AppLogger
  config.multiprocess_files_dir = 'tmp/prometheus_multiproc_dir'
  config.pid_provider = ::Prometheus::PidProvider.method(:worker_id)
end
```

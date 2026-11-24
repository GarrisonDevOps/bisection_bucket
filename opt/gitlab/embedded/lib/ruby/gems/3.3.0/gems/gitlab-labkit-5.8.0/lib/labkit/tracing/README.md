# Labkit::Tracing

The `Labkit::Tracing` module provides distributed tracing functionality for Ruby applications using the OpenTelemetry standard. It enables you to trace requests across multiple services and components, helping you understand application performance and debug issues in distributed systems.

## Overview

Distributed tracing allows you to track requests as they flow through your application and external services. The tracing module integrates with OpenTelemetry (OTLP) backends, and provides automatic instrumentation for:

- HTTP requests (Rack/Rails)
- Redis operations
- External HTTP requests
- Rails components (ActiveRecord, ActionView, ActiveSupport)

## Configuration

Tracing is controlled via an environment variable:

### Required Configuration

**`GITLAB_TRACING`** - Connection string for the tracing backend

Format: `otlp://<host:port>?<options>`

Example:
```bash
# OpenTelemetry with HTTP endpoint and service name
export GITLAB_TRACING="otlp://localhost:4318?service_name=my-api"

# Console exporter for development/testing (outputs to stdout)
export GITLAB_TRACING="otlp://console?service_name=my-api"

# Without service name (defaults to "labkit-service")
export GITLAB_TRACING="otlp://localhost:4318"
```

**Automatic Initialization**

When `GITLAB_TRACING` is set, LabKit automatically creates and configures a tracer:

- **Rails applications**: Railtie automatically inserts Labkit::Tracing::RackMiddleware into the middleware stack
- **Non-Rails applications**: Tracer is auto-initialized, but `Labkit::Tracing::RackMiddleware` must be manually added to your middleware stack for HTTP request tracing (see [Rack Middleware](#rack-middleware))

Auto-initialization provides:
- Automatic tracer creation with connection string settings (sampler, exporter, service name)
- Service name from `service_name` query parameter (defaults to `"labkit-service"`)
- Selective OpenTelemetry instrumentation for components that don't conflict with LabKit:
  - `ConcurrentRuby`, `Net::HTTP`, `ActionPack`, `ActionMailer`, `ActiveJob`
- LabKit's own instrumentation for components it handles directly:
  - HTTP request tracing (RackMiddleware for Rails)
  - Rails components (ActiveRecord, ActionView, ActiveSupport) - if Rails is available
  - Redis instrumentation - if Redis gem is loaded
  - External HTTP instrumentation (Net::HTTP, Excon, HTTPClient)
- Safe fallback if initialization fails (no-op tracer)

### Optional Configuration

**`GITLAB_TRACING_INCLUDE_STACKTRACE`** - Comma-separated list of operation name prefixes to include stack traces

Example:
```bash
export GITLAB_TRACING_INCLUDE_STACKTRACE="redis,active_record"
```

## Connection String Configuration

The following connection string formats and query parameters are supported:

### Endpoints

- **HTTP Endpoint** - OTLP HTTP collector endpoint (default port: 4318)
  - Example: `otlp://localhost:4318`
  - Example with custom path: `otlp://localhost:4318/v1/traces`
  - Example with authentication: `otlp://user:password@collector.example.com:4318`

- **Console Exporter** - Output spans to stdout (development/testing only)
  - Example: `otlp://console`
  - **Use Case**: Local development, debugging, automated testing
  - **Behavior**: Outputs spans immediately to stdout with no remote export
  - **Benefits**: No external collector required, instant feedback, simple debugging


### Sampling

**Default Behavior:** When no sampler is specified, probabilistic sampling is used with a **0.1% sample rate** (1 in 1000 traces).

- **`sampler`** - Sampling strategy (`probabilistic` or `const`)
  - `probabilistic` - Sample a percentage of traces (default: 0.1%)
  - `const` - Sample all traces (when `sampler_param=1`) or none (when `sampler_param=0`)

- **`sampler_param`** - Parameter for the sampler
  - For `probabilistic`: rate between 0.0 and 1.0 (e.g., `0.1` = 10%)
  - For `const`: `1` (sample all) or `0` (sample none)

- **`service_name`** - Set the service name for this tracer (defaults to `"labkit-service"`)
  - The service name identifies your application in traces
  - Appears in trace UI and helps distinguish between services
  - Example: `service_name=checkout-api`

### Examples

```bash
# Development: Console output with full sampling and service name
export GITLAB_TRACING="otlp://console?service_name=my-app&sampler=const&sampler_param=1"

# Staging: HTTP endpoint with probabilistic sampling (1%)
export GITLAB_TRACING="otlp://collector.staging.example.com:4318?service_name=my-app&sampler=probabilistic&sampler_param=0.01"

# Production: HTTP endpoint with custom path and authentication
export GITLAB_TRACING="otlp://user:pass@collector.prod.example.com:4318/v1/traces?service_name=my-app&sampler=probabilistic&sampler_param=0.001"

# Testing: Console output with no sampling (useful for test verification)
export GITLAB_TRACING="otlp://console?service_name=my-app&sampler=const&sampler_param=0"
```

## Using OpenTelemetry APIs Directly

**Labkit is a thin wrapper around OpenTelemetry** - it handles initialization and provides sensible defaults, but you should use OpenTelemetry APIs directly for instrumentation.

### What Labkit Provides Out-of-the-Box

- **Automatic tracer initialization** from `GITLAB_TRACING` environment variable
- **Connection string parsing** for OTLP endpoints, samplers, and exporters
- **Default service name** (`labkit-service`) with query parameter override
- **Automatic instrumentation** for Rails, Redis, and external HTTP requests
- **Correlation ID injection** into all spans automatically
- **Security sanitization** for SQL queries, URLs, and Redis commands

### What You Should Use Directly

For all span creation and manipulation, use OpenTelemetry APIs:

```ruby
# Get Labkit-configured tracer
tracer = Labkit::Tracing.tracer

# Get current span
span = Labkit::Tracing.current_span

# Use OpenTelemetry APIs for everything else
tracer.in_span("operation") do |span|
  span.set_attribute("key", "value")
  span.add_event("event_name", attributes: { "detail" => "info" })
  span.record_exception(exception) if exception
  span.status = OpenTelemetry::Trace::Status.error("Failed")
end
```

**Benefits of direct OTel usage:**
- Full access to OpenTelemetry capabilities (events, exceptions, status, links)
- Works with all OpenTelemetry documentation and examples
- Compatible with other OTel libraries and tools
- Future-proof as OpenTelemetry evolves

### Context Sharing

Labkit and OpenTelemetry share the same global tracer provider and context propagation mechanism. This means spans created by Labkit are visible to OpenTelemetry APIs and vice versa.

This seamless integration means you can:
- Use Labkit for initialization and defaults
- Use OpenTelemetry APIs directly for instrumentation
- Mix both approaches in the same codebase
- Trust that context propagates correctly across both

## Usage

### Automatic Initialization (Default Behavior)

When `GITLAB_TRACING` is set, LabKit automatically creates and configures a tracer:

```bash
# Set environment variable with service name
export GITLAB_TRACING="otlp://localhost:4318?service_name=my-api&sampler=probabilistic&sampler_param=0.01"

# Or use default service name "labkit-service"
export GITLAB_TRACING="otlp://localhost:4318"
```

**Rails Applications:**
- Initialization happens automatically during Rails boot via Railtie
- Runs after all other gem initializers (including `opentelemetry-instrumentation-rails`)
- LabKit's TracerProvider is the final configuration used by the application
- **No application code changes required** - just set the environment variable

**Non-Rails Applications (Sinatra, Grape, standalone Ruby):**
- Tracer auto-initialization happens automatically when `require 'gitlab-labkit'` is called.
- However, you must manually add `Labkit::Tracing::RackMiddleware` to your middleware stack for HTTP request tracing. See the [Rack Middleware](#rack-middleware) section for details.

Auto-initialization:
- Creates tracer with connection string settings (sampler, exporter, endpoints)
- Uses service name from `service_name` query parameter (defaults to `"labkit-service"`)
- Enables selective OpenTelemetry instrumentation (non-conflicting with LabKit's own)
- Enables LabKit instrumentation for ActiveRecord, ActionView, ActiveSupport, Redis, and External HTTP
- Sets up the global `OpenTelemetry.tracer_provider`

### Automatic Rails Middleware Insertion

When using Rails, the `Labkit::Tracing::RackMiddleware` is automatically inserted into your middleware stack when `GITLAB_TRACING` is set. No manual configuration needed!

**How it works:**
- Detected automatically via Rails Railtie
- Inserted after `Labkit::Middleware::Rack` for proper correlation ID propagation
- Only activates when `GITLAB_TRACING` is set
- Logs insertion to Rails logger for visibility

**Middleware Positioning:**

The middleware is automatically inserted, but you can still customize its position if needed:

```ruby
# config/application.rb
module MyApp
  class Application < Rails::Application
    # Move tracing middleware before authentication for earlier tracing
    config.middleware.move_before AuthenticationMiddleware, Labkit::Tracing::RackMiddleware

    # Or move it after error handling
    config.middleware.move_after ErrorHandlingMiddleware, Labkit::Tracing::RackMiddleware
  end
end
```

**Note:** The middleware is automatically added, so you only need to use `move_before` or `move_after` if you need custom positioning. Don't use `insert_after` or `use` as that would duplicate the middleware.

### Manual Initialization (Override Auto-initialization)

You can override auto-initialization by calling `Factory.create_tracer` in your application initializers. This is useful when you need custom configuration:

```ruby
# config/initializers/tracing.rb
# Override auto-initialization with custom configuration
Labkit::Tracing::Factory.create_tracer("my-custom-service", ENV["GITLAB_TRACING"]) do |c|
  # Custom OTel instrumentation
  c.use 'OpenTelemetry::Instrumentation::ConcurrentRuby'
  c.use 'OpenTelemetry::Instrumentation::Sidekiq'

  # Add custom span processors
  c.add_span_processor(MyCustomProcessor.new)

  # Add additional resource attributes
  c.resource = c.resource.merge(
    OpenTelemetry::SDK::Resources::Resource.create(
      'deployment.environment' => Rails.env,
      'service.version' => MyApp::VERSION
    )
  )
end
```

**When to use manual initialization:**
- You need different OTel instrumentations than the defaults
- You need custom span processors
- You need to add resource attributes
- You want to override the service name from code instead of the connection string

**Note:** Manual calls to `Factory.create_tracer` reconfigure the global OpenTelemetry tracer provider. The last call wins, so manual initialization overrides auto-initialization.

### Manual Span Creation

Labkit provides setup and defaults, but you should use OpenTelemetry APIs directly for creating spans and adding instrumentation:

**Creating spans with the tracer:**

```ruby
# Get the tracer (configured by Labkit with connection string settings)
tracer = Labkit::Tracing.tracer

# Create a span with OpenTelemetry API
tracer.in_span("process_data", attributes: { "user_id" => user.id }) do |span|
  result = process_data(data)

  span.set_attribute("result_count", result.count)
  span.add_event("processing_complete", attributes: { "duration_ms" => 123 })

  result
end
```

**Working with the current span:**

```ruby
# Get the currently active span
span = Labkit::Tracing.current_span

# Check if the span is being recorded (respects sampling decisions)
if span.recording?
  span.set_attribute("expensive_data", compute_expensive_data)
  span.add_event("custom_event", attributes: { "key" => "value" })
end
```

**Creating child spans:**

```ruby
tracer = Labkit::Tracing.tracer

tracer.in_span("parent_operation") do |parent_span|
  # Child span is automatically created within parent context
  tracer.in_span("child_operation") do |child_span|
    child_span.set_attribute("type", "background")
    perform_operation
  end
end
```

### Initialization Order and Precedence

**Auto-initialization (all applications):**
1. Runs automatically when `require 'gitlab-labkit'` is called
2. Only runs if `GITLAB_TRACING` environment variable is set
3. Uses `service_name` query parameter or defaults to `"labkit-service"`
4. Enables selective OpenTelemetry instrumentation (ConcurrentRuby, Net::HTTP, ActionPack, ActionMailer, ActiveJob) to avoid conflicts with LabKit's own instrumentation
5. Enables LabKit instrumentation for ActiveRecord, ActionView, ActiveSupport, Redis, and External HTTP

**Additional Rails behavior:**
1. Railtie runs after user config initializers (via `initializer ... after: :load_config_initializers`)
2. Automatically inserts `Labkit::Tracing::RackMiddleware` into the middleware stack

**Manual initialization:**
1. Runs in your application initializer (e.g., `config/initializers/tracing.rb`)
2. Overrides auto-initialization by reconfiguring the global tracer provider
3. Last call to `Factory.create_tracer` wins

**Configuration precedence within a single `Factory.create_tracer` call:**
1. **GITLAB_TRACING connection string** settings are applied first:
   - Service name (from `service_name` query parameter or method parameter)
   - Sampler type and parameters (`sampler`, `sampler_param`)
   - Exporter endpoint, protocol, and authentication headers
   - Span processors with OTLP exporter

2. **Configuration block** runs second and can:
   - Add automatic instrumentation (`use`)
   - Add additional span processors
   - Merge additional resource attributes
   - Override service_name if explicitly set in the block

**Important:** Calling `Factory.create_tracer` multiple times will reconfigure the global OpenTelemetry tracer provider each time. Initialize tracing once during application startup.

### Checking if Current Request is Sampled

```ruby

# checks if span will actually record data
span = Labkit::Tracing.current_span
if span.recording?
  span.set_attribute("expensive_data", compute_expensive_data)
end
```

## Instrumentation

### Rack Middleware

Instrument incoming HTTP requests in Rack/Rails applications:

```ruby
# For non-Rails Rack apps (Sinatra, Grape, etc.) - in config.ru
use Labkit::Tracing::RackMiddleware

# For Rails apps: Middleware is automatically inserted when GITLAB_TRACING is set.
# No manual configuration needed! See "Automatic Rails Middleware Insertion" section.
```

This automatically:
- Extracts trace context from incoming requests
- Creates spans for HTTP requests with method and URL
- Adds HTTP status codes to spans
- Sanitizes sensitive parameters in URLs

### Rails Components

**Note:** With auto-initialization enabled (when `GITLAB_TRACING` is set), these LabKit-specific instrumentations are automatically enabled alongside OpenTelemetry's instrumentation. You only need to call these methods manually if you've disabled auto-initialization or need to control when instrumentation starts.

Both OpenTelemetry and LabKit instrumentation run side-by-side, providing complementary trace data:
- **OpenTelemetry Rails instrumentation**: Provides standardized, method-level traces using semantic conventions
- **LabKit instrumentation**: Adds GitLab-specific details like SQL fingerprints, sanitized queries, and enhanced metadata

#### ActiveRecord (Database Queries)

```ruby
# Only needed if auto-initialization is disabled or you need manual control
unsubscribe = Labkit::Tracing::Rails::ActiveRecord::Subscriber.instrument

# Later, to stop instrumentation:
unsubscribe.call
```

Traces:
- SQL queries with sanitized statements
- Query fingerprints (via PgQuery)
- Connection IDs
- Cached query indicators

#### ActionView (Template Rendering)

```ruby
# Only needed if auto-initialization is disabled or you need manual control
unsubscribe = Labkit::Tracing::Rails::ActionView::Subscriber.instrument

# Later, to stop instrumentation:
unsubscribe.call
```

Traces:
- Template rendering
- Partial rendering
- Collection rendering
- Template identifiers and layouts

#### ActiveSupport (Caching)

```ruby
# Only needed if auto-initialization is disabled or you need manual control
unsubscribe = Labkit::Tracing::Rails::ActiveSupport::Subscriber.instrument

# Later, to stop instrumentation:
unsubscribe.call
```

Traces:
- Cache reads (with hit/miss information)
- Cache writes
- Cache deletes
- Cache fetch operations
- Cache key information

### Redis

**Note:** Redis instrumentation is automatically enabled when `GITLAB_TRACING` is set and the Redis gem is loaded.

```ruby
# Only needed if auto-initialization is disabled or you need manual control
Labkit::Tracing::Redis.instrument
```

This automatically traces:
- Individual Redis commands
- Pipelined commands (up to 5 commands shown)
- Connection details (host, port, scheme)
- Sanitized command arguments (sensitive commands like AUTH and EVAL are masked)

### External HTTP Requests

**Note:** External HTTP instrumentation is automatically enabled when `GITLAB_TRACING` is set.

Instrument outgoing HTTP requests made by Net::HTTP, Excon, and HTTPClient:

```ruby
# Only needed if auto-initialization is disabled or you need manual control
unsubscribe = Labkit::Tracing::ExternalHttp.instrument

# Later, to stop instrumentation:
unsubscribe.call
```

Automatically traces:
- HTTP method and URL
- Response status codes
- Host, port, and scheme
- Proxy information (if applicable)

## Architecture

### Core Components

- **`Labkit::Tracing`** - Main module with configuration and utility methods
- **`Labkit::Tracing::Factory`** - Creates and configures tracer instances
- **`Labkit::Tracing::OpenTelemetryFactory`** - OpenTelemetry-specific tracer configuration
- **`Labkit::Tracing::TracingUtils`** - Utilities for span management
- **`Labkit::Tracing::AbstractInstrumenter`** - Base class for ActiveSupport::Notifications instrumenters

### Instrumentation Pattern

Most instrumenters follow this pattern:

1. Subscribe to `ActiveSupport::Notifications` events
2. Create spans when events start
3. Add tags and metadata to spans
4. Handle exceptions and log them to spans
5. Close spans when events finish

### Span Lifecycle

Each span automatically includes:
- **Correlation ID** - Links traces to logs and other telemetry
- **Common tags** - Component, operation type, etc.
- **Exception handling** - Errors are logged with stack traces
- **Stack traces** - Optional, based on `GITLAB_TRACING_INCLUDE_STACKTRACE`

## Security and Privacy

The tracing module includes built-in sanitization:

- **SQL queries** - Sanitized using `Labkit::Logging::Sanitizer.sanitize_sql`
- **URLs** - Filtered parameters removed (e.g., tokens, passwords)
- **Redis commands** - Sensitive commands (AUTH, EVAL) are masked
- **Redis arguments** - Long arguments are truncated with masking
- **Exception messages** - Sanitized using `Labkit::Logging::Sanitizer.sanitize_field`

## Performance Considerations

### Sampling

Use sampling to control overhead:

```bash
# Default: 0.1% sampling (no sampler specified)
export GITLAB_TRACING="otlp://localhost:4318"

# Trace 1% of requests
export GITLAB_TRACING="otlp://localhost:4318?sampler=probabilistic&sampler_param=0.01"

# Trace all requests (high overhead)
export GITLAB_TRACING="otlp://localhost:4318?sampler=const&sampler_param=1"
```

### Conditional Expensive Operations

Use OpenTelemetry's `span.recording?` to check if expensive operations should be performed:

```ruby
span = Labkit::Tracing.current_span

if span.recording?
  # Only execute when trace is being captured and sampled
  span.set_attribute("expensive_data", compute_expensive_data)
  span.add_event("detailed_event", attributes: expensive_analysis)
end
```

### Batch Span Processing

Spans are batched and exported to the OTLP endpoint at regular intervals to optimize performance and network usage.

## Integration with Correlation

Tracing integrates with `Labkit::Correlation` to link traces with logs and other telemetry:

```ruby
# Correlation ID is automatically added to all spans
correlation_id = Labkit::Correlation::CorrelationId.current_id
# This ID appears in both logs and traces
```

## Example: Complete Setup

### Development Environment with Console Exporter (Automatic)

```ruby
# config/application.rb
module MyApp
  class Application < Rails::Application
    # Labkit::Tracing::RackMiddleware is automatically inserted!
    # No manual configuration needed.

    # Optional: Customize middleware position if needed
    # config.middleware.move_after SomeOtherMiddleware, Labkit::Tracing::RackMiddleware
  end
end

# .env.development
# GITLAB_TRACING="otlp://console?service_name=my-rails-app&sampler=const&sampler_param=1"
```

**That's it!** Both the tracer and middleware are automatically configured when the gem loads. This setup outputs all trace spans directly to your development console/logs, making it easy to:
- Debug request flows without external tools
- Verify instrumentation is working correctly
- Test tracing configuration changes
- Develop and debug trace-dependent features

### Production Environment (Automatic with Custom Metadata)

Most applications can use automatic initialization:

```ruby
# config/application.rb
module MyApp
  class Application < Rails::Application
    # Labkit::Tracing::RackMiddleware is automatically inserted!
    # No manual configuration needed.
  end
end

# .env.production
# GITLAB_TRACING="otlp://collector.example.com:4318?service_name=my-rails-app&sampler=probabilistic&sampler_param=0.01"
```

If you need to add custom metadata (deployment environment, version, etc.), override tracer initialization:

```ruby
# config/initializers/tracing.rb

Labkit::Tracing::Factory.create_tracer("my-rails-app", ENV["GITLAB_TRACING"]) do |c|
  # Selective instrumentation (avoid conflicting with LabKit's own instrumentation
  # for ActiveRecord, ActionView, ActiveSupport, Redis, Rack, and Sidekiq)
  c.use("OpenTelemetry::Instrumentation::ConcurrentRuby")
  c.use("OpenTelemetry::Instrumentation::Net::HTTP")
  c.use("OpenTelemetry::Instrumentation::ActionPack") if defined?(ActionPack)
  c.use("OpenTelemetry::Instrumentation::ActionMailer") if defined?(ActionMailer)
  c.use("OpenTelemetry::Instrumentation::ActiveJob") if defined?(ActiveJob)

  # Add deployment metadata
  c.resource = c.resource.merge(
    OpenTelemetry::SDK::Resources::Resource.create(
      'deployment.environment' => Rails.env,
      'service.version' => MyApp::VERSION
    )
  )
end

# .env.production
# GITLAB_TRACING="otlp://collector.example.com:4318?service_name=my-rails-app&sampler=probabilistic&sampler_param=0.01"
```

Note: Middleware is still automatically inserted even with custom tracer initialization.

### With Custom Instrumentation (Manual Override)

If you want to control exactly which OTel components are instrumented, override tracer initialization:

**Important:** When you manually call `Factory.create_tracer`, auto-initialization still runs but is replaced by your manual configuration. The LabKit-specific instrumentation (Rails, Redis, ExternalHttp) is still automatically enabled unless you explicitly disable auto-initialization.

```ruby
# config/initializers/tracing.rb
# Override auto-initialization for custom OpenTelemetry instrumentation
Labkit::Tracing::Factory.create_tracer("my-rails-app", ENV["GITLAB_TRACING"]) do |c|
  # Only enable the OTel instrumentations you need
  c.use 'OpenTelemetry::Instrumentation::ConcurrentRuby'
  c.use 'OpenTelemetry::Instrumentation::Sidekiq'
end

# LabKit instrumentation is already enabled automatically during auto-initialization.
# Only call these manually if you need to control timing or disable auto-initialization:
# Rails.application.config.after_initialize do
#   Labkit::Tracing::Rails::ActiveRecord::Subscriber.instrument
#   Labkit::Tracing::Rails::ActionView::Subscriber.instrument
#   Labkit::Tracing::Rails::ActiveSupport::Subscriber.instrument
#   Labkit::Tracing::ExternalHttp.instrument
#   Labkit::Tracing::Redis.instrument
# end
```

Note: Both middleware insertion and LabKit instrumentation are automatically handled even with manual tracer initialization.

## Troubleshooting

### Tracing Not Working

1. Verify `GITLAB_TRACING` is set correctly:
   ```ruby
   puts Labkit::Tracing.connection_string
   puts Labkit::Tracing.enabled?
   ```

2. Check for tracer creation errors in logs (warnings are emitted on failure during auto-initialization)

3. Verify the OTLP collector is reachable

### Middleware Not Tracing Requests (Rails)

If you're not seeing HTTP request traces in Rails:

1. Verify the middleware is in your Rails stack:
   ```ruby
   # In Rails console
   Rails.application.middleware.middlewares
   # Should include Labkit::Tracing::RackMiddleware
   ```

2. Check Rails logs for auto-insertion message:
    ```
    Labkit::Tracing::RackMiddleware automatically inserted after Labkit::Middleware::Rack
    ```

3. If using custom middleware positioning, verify the order is correct:
   ```bash
   # View middleware stack with positions
   bundle exec rake middleware
   ```

4. Ensure `GITLAB_TRACING` is set in your environment (not just in `.env` files that might not be loaded)

### Missing Spans

1. Ensure instrumentation is called after dependencies are loaded
2. Verify tracing is properly initialized and enabled:
   ```ruby
   Labkit::Tracing.enabled?
   ```

### Middleware Works But No Traces Appear

If your application runs without errors but you don't see traces in your backend (OTLP collector):

**1. Verify the tracer provider is initialized:**

```ruby
OpenTelemetry.tracer_provider.class
# Expected: OpenTelemetry::SDK::Trace::TracerProvider
# Problem:  OpenTelemetry::Internal::ProxyTracerProvider (auto-initialization failed)
```

**2. Check for auto-initialization warnings in logs:**

Auto-initialization warnings indicate what went wrong:
```
Labkit::Tracing auto-initialization failed: <error message>
```

**3. Common causes:**

- `GITLAB_TRACING` environment variable not set or not visible to the process
- Connection string format error (should start with `otlp://`)
- OpenTelemetry gem dependency issues
- OTLP collector not reachable

**4. Test with console exporter:**

Use the console exporter to verify tracing works locally:
```bash
export GITLAB_TRACING="otlp://console?service_name=test&sampler=const&sampler_param=1"
```

You should see trace output in your application logs.

### High Overhead

1. Reduce sampling rate:
   ```bash
   export GITLAB_TRACING="otlp://localhost:4318?sampler=probabilistic&sampler_param=0.001"
   ```

2. Disable stack traces or limit to specific operations:
   ```bash
   export GITLAB_TRACING_INCLUDE_STACKTRACE=""
   ```

## References

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/languages/ruby/)
- [OpenTelemetry Protocol (OTLP) Specification](https://opentelemetry.io/docs/specs/otlp/)
- [Rails Instrumentation Guide](https://guides.rubyonrails.org/active_support_instrumentation.html)

# frozen_string_literal: true

require "active_support/core_ext/module/attribute_accessors"

module Labkit
  # Tracing provides distributed tracing functionality
  module Tracing
    autoload :AbstractInstrumenter, "labkit/tracing/abstract_instrumenter"
    autoload :AutoInitialize, "labkit/tracing/auto_initialize"
    autoload :TracingCommon, "labkit/tracing/tracing_common"
    autoload :Factory, "labkit/tracing/factory"
    autoload :GRPC, "labkit/tracing/grpc"
    autoload :GRPCInterceptor, "labkit/tracing/grpc_interceptor" # Deprecated
    autoload :JaegerFactory, "labkit/tracing/jaeger_factory"
    autoload :OpenTelemetryFactory, "labkit/tracing/open_telemetry_factory"
    autoload :OpenTracingFactory, "labkit/tracing/open_tracing_factory"
    autoload :RackMiddleware, "labkit/tracing/rack_middleware"
    autoload :Rails, "labkit/tracing/rails"
    autoload :Redis, "labkit/tracing/redis"
    autoload :ExternalHttp, "labkit/tracing/external_http"
    autoload :Sidekiq, "labkit/tracing/sidekiq"
    autoload :TracingUtils, "labkit/tracing/tracing_utils"

    module Adapters
      autoload :BaseSpan, "labkit/tracing/adapters/base_span"
      autoload :OpentelemetrySpan, "labkit/tracing/adapters/opentelemetry_span"
      autoload :OpentracingSpan, "labkit/tracing/adapters/opentracing_span"
      autoload :BaseTracer, "labkit/tracing/adapters/base_tracer"
      autoload :OpentelemetryTracer, "labkit/tracing/adapters/opentelemetry_tracer"
      autoload :OpentracingTracer, "labkit/tracing/adapters/opentracing_tracer"
    end

    # Must be a String, not Symbol, as OpenTelemetry requires resource attribute values
    # to be strings, integers, floats, or booleans
    DEFAULT_SERVICE_NAME = "labkit-service"

    # Module-level attribute for storing the configured service name
    # Set by Factory.create_tracer when a tracer is created
    mattr_accessor :configured_service_name, default: DEFAULT_SERVICE_NAME

    # Tracing is only enabled when the `GITLAB_TRACING` env var is configured.
    def self.enabled?
      connection_string.present?
    end

    def self.connection_string
      ENV["GITLAB_TRACING"]
    end

    def self.otlp_connection?(connection_string = ENV["GITLAB_TRACING"])
      connection_string.to_s.start_with?("#{OpenTelemetryFactory::OTLP_SCHEME}://")
    end

    def self.opentracing_connection?(connection_string = ENV["GITLAB_TRACING"])
      connection_string.to_s.start_with?("#{OpenTracingFactory::OPENTRACING_SCHEME}://")
    end

    # Returns the tracing URL template from the GITLAB_TRACING_URL environment variable.
    #
    # @note This method is only useful with OpenTracing and Jaeger. It does not work with
    #   OpenTelemetry backends, as they expect trace_id (W3C standard) rather than
    #   correlation_id (GitLab-specific) for trace lookups.
    #
    # @return [String, nil] The URL template with placeholders for {{ correlation_id }} and {{ service }}
    def self.tracing_url_template
      ENV["GITLAB_TRACING_URL"]
    end

    # Check if the current request is being traced.
    def self.sampled?
      context = TracingUtils.tracer.active_span&.context
      context&.respond_to?(:sampled?) && context&.sampled?
    end

    def self.stacktrace_operations
      @stacktrace_operations ||= Set.new(ENV["GITLAB_TRACING_INCLUDE_STACKTRACE"].to_s.split(",").map(&:strip))
    end

    # Checks if tracing URL generation is enabled.
    #
    # @note This method is only useful with OpenTracing and Jaeger. It does not work with
    #   OpenTelemetry backends, as they expect trace_id (W3C standard) rather than
    #   correlation_id (GitLab-specific) for trace lookups.
    #
    # @return [Boolean] true if both tracing and URL template are configured
    # @see tracing_url
    def self.tracing_url_enabled?
      enabled? && tracing_url_template.present?
    end

    # Generates a URL to view the current trace in a tracing UI.
    #
    # This method substitutes {{ correlation_id }} and {{ service }} placeholders in the
    # GITLAB_TRACING_URL template with the current correlation ID and provided service name.
    #
    # @note This method is only useful with OpenTracing and Jaeger. It does not work with
    #   OpenTelemetry backends because:
    #   - Uses correlation_id (GitLab-specific request ID) instead of trace_id (W3C standard)
    #   - Modern tracing UIs (Jaeger with OTLP, Grafana Tempo, etc.) expect trace_id for lookups
    #   - Only Jaeger's legacy OpenTracing integration supports correlation_id-based URLs
    #
    # @param service_name [String] The name of the service to include in the URL
    # @return [String, nil] The generated URL, or nil if tracing URL is not enabled
    #
    # @example With OpenTracing/Jaeger (supported)
    #   ENV["GITLAB_TRACING_URL"] = "https://jaeger.example.com/trace?correlationId={{ correlation_id }}"
    #   Labkit::Tracing.tracing_url("my-service")
    #   # => "https://jaeger.example.com/trace?correlationId=abc123"
    def self.tracing_url(service_name)
      return unless tracing_url_enabled?

      correlation_id = Labkit::Correlation::CorrelationId.current_id.to_s

      # Avoid using `format` since it can throw TypeErrors
      # which we want to avoid on unsanitised env var input
      tracing_url_template.to_s
        .gsub("{{ correlation_id }}", correlation_id)
        .gsub("{{ service }}", service_name)
    end

    # Returns the underlying tracer implementation from the tracing library in use.
    # This provides direct access to the native tracer API when LabKit's abstraction
    # is insufficient for advanced use cases.
    #
    # @example Using OpenTelemetry-specific APIs
    #   tracer = Labkit::Tracing.tracer
    #   tracer.in_span("custom-span") do |span|
    #     span.add_event("custom-event", attributes: { "key" => "value" })
    #   end
    #
    # @return [Object] The tracer implementation:
    #   - OpenTelemetry::SDK::Trace::Tracer when using OTLP connection
    #   - No-op tracer when tracing is not configured
    def self.tracer
      TracingUtils.tracer.tracer
    end

    # Returns the currently active span from OpenTelemetry.
    # This provides direct access to the OpenTelemetry span API.
    #
    # @example Adding attributes to the current span
    #   span = Labkit::Tracing.current_span
    #   span.set_attribute("user.id", user.id) if span.recording?
    #
    # @example Adding events
    #   span = Labkit::Tracing.current_span
    #   span.add_event("cache_miss", attributes: { "key" => cache_key })
    #
    # @example Conditional expensive operations
    #   span = Labkit::Tracing.current_span
    #   if span.recording?
    #     span.set_attribute("expensive_data", compute_expensive_data)
    #   end
    #
    # @return [OpenTelemetry::Trace::Span, nil] The current span (may be a no-op span when tracing is disabled, or nil when using OpenTracing)
    def self.current_span
      return nil if opentracing_connection?

      require "opentelemetry/sdk"
      OpenTelemetry::Trace.current_span
    end

    # This will run a block with a span
    # @param operation_name [String] The operation name for the span
    # @param tags [Hash] Tags to assign to the span
    # @param child_of [SpanContext, Span] SpanContext that acts as a parent to
    #  the newly-started span. If a span instance is provided, its
    #  context is automatically substituted.
    def self.with_tracing(**kwargs, &block)
      TracingUtils.with_tracing(**kwargs, &block)
    end
  end
end

require "labkit/tracing/railtie" if defined?(Rails::Railtie)

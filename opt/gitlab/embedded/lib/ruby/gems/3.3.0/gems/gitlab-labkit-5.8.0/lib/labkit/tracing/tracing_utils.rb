# frozen_string_literal: true

require "uri"
require "active_support/core_ext/string/starts_ends_with"
require "opentracing"

module Labkit
  module Tracing
    # Internal methods for tracing. This is not part of the LabKit public API.
    # For internal usage only
    class TracingUtils
      # Convience method for running a block with a span
      def self.with_tracing(operation_name:, tags:, child_of: nil)
        tracer.in_span(operation_name, child_of: child_of, tags: tags) do |span|
          log_common_fields_on_span(span, operation_name)

          begin
            yield span
          rescue StandardError => e
            span.set_error(e)
            raise e
          end
        end
      end

      # Obtain a tracer instance
      #
      # Returns the appropriate tracer based on connection string configuration:
      # - OpenTelemetry (OTLP): When GITLAB_TRACING uses otlp:// scheme
      # - OpenTracing: When GITLAB_TRACING uses opentracing:// scheme or not set
      #
      # For OpenTelemetry, the tracer's instrumentation scope name is determined by:
      # - The service_name passed to Factory.create_tracer
      # - Falls back to DEFAULT_SERVICE_NAME if Factory was not used
      #
      # Both OpenTelemetry and OpenTracing provide no-op tracers by default:
      # - OpenTelemetry: Uses ProxyTracerProvider until SDK is configured
      # - OpenTracing: Uses default no-op global_tracer
      #
      # This allows spans to be created but not exported when tracing is not initialized,
      # letting the application run safely while producing no trace data.
      def self.tracer
        @tracer ||=
          if Tracing.otlp_connection?
            require "opentelemetry/sdk"

            otel_tracer = OpenTelemetry.tracer_provider.tracer(Tracing.configured_service_name)
            Adapters::OpentelemetryTracer.new(otel_tracer)
          else
            Adapters::OpentracingTracer.new(OpenTracing.global_tracer)
          end
      end

      # Generate a span retrospectively
      def self.postnotify_span(operation_name, start_time, end_time, tags: nil, child_of: nil, exception: nil)
        span = tracer.start_span(operation_name, child_of: child_of, tags: tags, start_time: start_time)

        log_common_fields_on_span(span, operation_name)
        span.set_error(exception)

        span.finish(end_timestamp: end_time)
      end

      # Add common fields to a span
      def self.log_common_fields_on_span(span, operation_name)
        correlation_id = Labkit::Correlation::CorrelationId.current_id

        span.set_tag("correlation_id", correlation_id) if correlation_id
        span.log_event("stack", stack: caller.join('\n')) if include_stacktrace?(operation_name)
      end

      def self.include_stacktrace?(operation_name)
        @include_stacktrace ||= Hash.new do |result, name|
          result[name] = Tracing.stacktrace_operations.any? { |stacktrace_operation| name.starts_with?(stacktrace_operation) }
        end

        @include_stacktrace[operation_name]
      end

      def self.parse_query_string(query)
        return {} unless query

        URI.decode_www_form(query).each_with_object({}) { |(k, v), h| h[k.to_sym] ||= v }
      end
    end
  end
end

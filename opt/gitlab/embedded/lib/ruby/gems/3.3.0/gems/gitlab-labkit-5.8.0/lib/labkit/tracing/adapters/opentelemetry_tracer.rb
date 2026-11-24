# frozen_string_literal: true

# Internal adapter for OpenTelemetry tracer compatibility.
# This is not part of the public Labkit API.
#
# Applications should use OpenTelemetry APIs directly via:
#   - Labkit::Tracing.tracer (returns OpenTelemetry::Trace::Tracer)
#   - Labkit::Tracing.current_span (returns OpenTelemetry::Trace::Span)
#
# These adapters exist for:
#   - Internal Labkit instrumentation (Rails, Redis, etc.)
#   - Backward compatibility with OpenTracing connections
#
# @api private

module Labkit
  module Tracing
    module Adapters
      class OpentelemetryTracer < BaseTracer
        def start_span(operation_name, child_of: nil, tags: {}, start_time: nil)
          attributes = tags || {}
          opts = { attributes: attributes }
          opts[:with_parent] = child_of if child_of
          opts[:start_timestamp] = start_time if start_time

          span = tracer.start_span(operation_name, **opts)
          OpentelemetrySpan.new(span)
        end

        def in_span(operation_name, child_of: nil, tags: {})
          attributes = tags || {}

          if child_of
            span = tracer.start_span(operation_name, with_parent: child_of, attributes: attributes)
            ctx = OpenTelemetry::Trace.context_with_span(span)

            result = nil
            OpenTelemetry::Context.with_current(ctx) do
              adapter = OpentelemetrySpan.new(span)
              result = yield(adapter)
            end

            span.finish
            result
          else
            tracer.in_span(operation_name, attributes: attributes) do |span|
              adapter = OpentelemetrySpan.new(span)
              yield(adapter)
            end
          end
        end

        def extract_context(carrier, format: nil) # rubocop:disable Lint/UnusedMethodArgument
          # Format parameter is ignored for OpenTelemetry - propagation format is configured
          # globally via OTEL_PROPAGATORS environment variable, not per-call like OpenTracing.
          # The parameter exists only for BaseTracer API compatibility.
          OpenTelemetry.propagation.extract(carrier)
        end

        def inject_context(span_wrapper, carrier, format: nil) # rubocop:disable Lint/UnusedMethodArgument
          # Format parameter is ignored for OpenTelemetry - propagation format is configured
          # globally via OTEL_PROPAGATORS environment variable, not per-call like OpenTracing.
          # The parameter exists only for BaseTracer API compatibility.
          #
          # span_wrapper is expected to be a BaseSpan (e.g., OpentelemetrySpan) that wraps
          # the actual OpenTelemetry span. We unwrap it to get the OTel span object.
          span = span_wrapper.respond_to?(:span) ? span_wrapper.span : span_wrapper
          context = OpenTelemetry::Trace.context_with_span(span)
          OpenTelemetry.propagation.inject(carrier, context: context)
        end

        def active_span
          OpenTelemetry::Trace.current_span
        end

        def start_active_span(operation_name, tags: nil)
          attributes = tags || {}
          raw_span = tracer.start_span(operation_name, attributes: attributes)
          ctx = OpenTelemetry::Trace.context_with_span(raw_span)
          token = OpenTelemetry::Context.attach(ctx)

          OpenTelemetryScope.new(raw_span, token)
        end

        class OpenTelemetryScope
          attr_reader :span

          def initialize(raw_span, token)
            @span = OpentelemetrySpan.new(raw_span)
            @raw_span = raw_span
            @token = token
          end

          def set_tag(key, value)
            span.set_tag(key, value)
          end

          def set_error(exception)
            span.set_error(exception)
          end

          def log_event(name, **attributes)
            span.log_event(name, **attributes)
          end

          def close
            @raw_span.finish
            OpenTelemetry::Context.detach(@token)
          end
        end
      end
    end
  end
end

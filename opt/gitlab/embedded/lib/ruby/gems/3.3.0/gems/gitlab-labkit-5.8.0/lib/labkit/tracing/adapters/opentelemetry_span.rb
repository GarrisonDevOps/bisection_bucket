# frozen_string_literal: true

# Internal adapter for OpenTelemetry span compatibility.
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
      class OpentelemetrySpan < BaseSpan
        def set_tag(key, value)
          span.set_attribute(key, value)
        end

        def log_event(name, **attributes)
          span.add_event(name, attributes: stringify_keys(attributes))
        end

        def set_error(exception)
          return if exception.blank?

          span.set_attribute("error", true)
          span.add_event("exception", attributes: stringify_keys(kv_tags_for_exception(exception)))
        end

        def finish(**opts)
          if opts[:end_timestamp]
            span.finish(end_timestamp: opts[:end_timestamp])
          else
            span.finish
          end
        end

        def close(**opts)
          finish(**opts)
        end

        def context
          span.context
        end

        private

        def stringify_keys(hash)
          hash.transform_keys(&:to_s)
        end

        def kv_tags_for_exception(exception)
          case exception
          when Exception
            {
              event: "error",
              'error.kind': exception.class.to_s,
              message: Labkit::Logging::Sanitizer.sanitize_field(exception.message),
              stack: exception.backtrace&.join('\n')
            }
          else
            {
              event: "error",
              'error.kind': exception.class.to_s,
              'error.object': Labkit::Logging::Sanitizer.sanitize_field(exception.to_s)
            }
          end
        end
      end
    end
  end
end

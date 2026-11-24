# frozen_string_literal: true

module Labkit
  module Tracing
    module Adapters
      class OpentracingSpan < BaseSpan
        attr_reader :scope

        def initialize(span_or_scope)
          if span_or_scope.respond_to?(:span)
            @scope = span_or_scope
            @span = span_or_scope.span
          else
            @scope = nil
            @span = span_or_scope
          end
        end

        def set_tag(key, value)
          span.set_tag(key, value)
        end

        def log_event(name, **attributes)
          span.log_kv(**attributes, event: name)
        end

        def set_error(exception)
          return if exception.blank?

          span.set_tag("error", true)
          span.log_kv(**kv_tags_for_exception(exception))
        end

        def finish(**opts)
          if opts[:end_timestamp]
            span.finish(end_time: opts[:end_timestamp])
          else
            span.finish
          end

          scope&.close
        end

        def close
          finish
        end

        def context
          span.context
        end

        private

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

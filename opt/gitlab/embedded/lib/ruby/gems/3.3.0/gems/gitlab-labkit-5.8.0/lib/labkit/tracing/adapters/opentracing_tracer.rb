# frozen_string_literal: true

module Labkit
  module Tracing
    module Adapters
      class OpentracingTracer < BaseTracer
        def start_span(operation_name, child_of: nil, tags: {}, start_time: nil)
          opts = {}
          opts[:child_of] = child_of if child_of
          opts[:tags] = tags if tags
          opts[:start_time] = start_time if start_time

          span = tracer.start_span(operation_name, **opts)
          OpentracingSpan.new(span)
        end

        def in_span(operation_name, child_of: nil, tags: {})
          scope = tracer.start_active_span(operation_name, child_of: child_of, tags: tags)
          adapter = OpentracingSpan.new(scope)

          begin
            yield(adapter)
          ensure
            adapter.finish
          end
        end

        def extract_context(carrier, format: OpenTracing::FORMAT_TEXT_MAP)
          tracer.extract(format, carrier)
        end

        def inject_context(span_context, carrier, format: OpenTracing::FORMAT_TEXT_MAP)
          tracer.inject(span_context, format, carrier)
        end

        def active_span
          span = OpenTracing.active_span
          OpentracingSpan.new(span) if span
        end

        def start_active_span(operation_name, tags: nil)
          scope = if tags
                    OpenTracing.start_active_span(operation_name, tags: tags)
                  else
                    OpenTracing.start_active_span(operation_name)
                  end

          OpentracingSpan.new(scope)
        end
      end
    end
  end
end

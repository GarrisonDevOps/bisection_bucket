# frozen_string_literal: true

module Labkit
  module Tracing
    module Adapters
      class BaseTracer
        attr_reader :tracer

        def initialize(tracer)
          @tracer = tracer
        end

        def start_span(_operation_name, child_of: nil, tags: {}, start_time: nil)
          raise NotImplementedError, "#{self.class.name}#start_span must be implemented"
        end

        def in_span(_operation_name, child_of: nil, tags: {}, &_block)
          raise NotImplementedError, "#{self.class.name}#in_span must be implemented"
        end

        def extract_context(_carrier, format: nil)
          raise NotImplementedError, "#{self.class.name}#extract_context must be implemented"
        end

        def inject_context(_span_context, _carrier, format: nil)
          raise NotImplementedError, "#{self.class.name}#inject_context must be implemented"
        end

        def active_span
          raise NotImplementedError, "#{self.class.name}#active_span must be implemented"
        end

        def start_active_span(_operation_name, tags: nil)
          raise NotImplementedError, "#{self.class.name}#start_active_span must be implemented"
        end
      end
    end
  end
end

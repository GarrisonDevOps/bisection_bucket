# frozen_string_literal: true

module Labkit
  module Tracing
    module Adapters
      class BaseSpan
        attr_reader :span

        def initialize(span)
          @span = span
        end

        def set_tag(_key, _value)
          raise NotImplementedError, "#{self.class.name}#set_tag must be implemented"
        end

        def log_event(_name, **_attributes)
          raise NotImplementedError, "#{self.class.name}#log_event must be implemented"
        end

        def set_error(_exception)
          raise NotImplementedError, "#{self.class.name}#set_error must be implemented"
        end

        def finish(**_opts)
          raise NotImplementedError, "#{self.class.name}#finish must be implemented"
        end

        def context
          raise NotImplementedError, "#{self.class.name}#context must be implemented"
        end
      end
    end
  end
end

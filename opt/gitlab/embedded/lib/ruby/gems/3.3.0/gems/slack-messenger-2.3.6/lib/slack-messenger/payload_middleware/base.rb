# frozen_string_literal: true

module Slack
  class Messenger
    class PayloadMiddleware
      class Base
        class << self
          def middleware_name name
            PayloadMiddleware.register self, name.to_sym
          end

          def options default_opts
            @default_opts = default_opts
          end

          def default_opts
            @default_opts ||= {}
          end
        end

        attr_reader :messenger, :options

        def initialize messenger, opts={}
          @messenger = messenger
          @options  = self.class.default_opts.merge opts
        end

        def call _payload={}
          raise NoMethodError, "method `call` not defined for class #{self.class}"
        end
      end
    end
  end
end

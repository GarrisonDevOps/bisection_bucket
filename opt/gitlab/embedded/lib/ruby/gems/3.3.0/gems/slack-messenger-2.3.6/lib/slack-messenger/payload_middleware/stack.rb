# frozen_string_literal: true

module Slack
  class Messenger
    class PayloadMiddleware
      class Stack
        attr_reader :messenger,
                    :stack

        def initialize messenger
          @messenger = messenger
          @stack    = []
        end

        def set *middlewares
          middlewares =
            if middlewares.length == 1 && middlewares.first.is_a?(Hash)
              middlewares.first
            else
              middlewares.flatten
            end

          @stack = middlewares.map do |key, opts|
            PayloadMiddleware.registry.fetch(key).new(*[messenger, opts].compact)
          end
        end

        def call payload={}
          result = stack.inject payload do |pld, middleware|
            as_array(pld).flat_map do |p|
              middleware.call(p)
            end
          end

          as_array(result)
        end

        private

          def as_array args
            if args.respond_to?(:to_ary)
              args.to_ary
            else
              [args]
            end
          end
      end
    end
  end
end

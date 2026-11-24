# frozen_string_literal: true

require "redis"

module Labkit
  module Tracing
    module Redis
      # RedisInterceptor is an interceptor for Redis to add distributed tracing.
      # It should be installed using the `Labkit::Tracing.instrument` method
      module RedisInterceptor
        def call(command)
          RedisInterceptorHelper.call_with_tracing(command, self) do
            # Note: when used without any arguments super uses the arguments given to the subclass method.
            super
          end
        end

        def call_pipeline(pipeline)
          RedisInterceptorHelper.call_pipeline_with_tracing(pipeline, self) do
            # Note: when used without any arguments super uses the arguments given to the subclass method.
            super
          end
        end
      end
    end
  end
end

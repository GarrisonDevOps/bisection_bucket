# frozen_string_literal: true

require "redis"

module Labkit
  module Tracing
    # The Redis interceptor will intercept all calls to Redis and instrument them for distributed tracing
    module Redis
      autoload :RedisInterceptor, "labkit/tracing/redis/redis_interceptor"
      autoload :RedisInterceptorHelper, "labkit/tracing/redis/redis_interceptor_helper"

      def self.instrument
        ::Redis::Client.prepend RedisInterceptor
      end
    end
  end
end

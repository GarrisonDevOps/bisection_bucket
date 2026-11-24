# frozen_string_literal: true

module RedisCloudAuth
  # A marshallable callable used as the redis-client `password`. redis-client
  # invokes `#call(username)` on every (re)connect, so returning a fresh access
  # token here authenticates new connections with a current token.
  #
  # It holds only the descriptor (simple values) and resolves the shared
  # provider from {Registry} at call time, so it can be Marshal.dump'd by
  # Sidekiq (unlike a Proc or a live provider object).
  class TokenCredential
    def initialize(descriptor)
      @descriptor = descriptor
    end

    def call(_username = nil)
      Registry.fetch(@descriptor).call.last
    rescue StandardError => e
      # redis-client only retries its own connection errors, and failsafes
      # (for example RedisCacheStore) only rescue RedisClient::Error. Map a
      # token-fetch failure to a connection error so a transient token-endpoint
      # outage is retried/handled as a reconnect rather than surfacing as a 500.
      # The original error is kept as the cause.
      require "redis-client"
      raise RedisClient::CannotConnectError, "failed to acquire Redis token: #{e.message}"
    end
  end
end

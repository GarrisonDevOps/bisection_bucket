# frozen_string_literal: true

require "logger"

require_relative "redis_cloud_auth/version"
require_relative "redis_cloud_auth/registry"
require_relative "redis_cloud_auth/token_credential"
require_relative "redis_cloud_auth/reauth_middleware"

# Rotating-token ("credentials provider") authentication for Redis, usable from
# any redis-client / redis-rb / Sidekiq consumer.
#
# A *provider* turns a cloud identity (Microsoft Entra, Amazon ElastiCache IAM,
# ...) into short-lived Redis credentials. It is a simple duck type:
#
#   provider.call        # => [username, password]  (fresh each call)
#   provider.expires_at  # => Time, or nil when no token has been fetched yet
#
# Two pieces wire a provider into a connection:
#
# * {TokenCredential} is a marshallable callable used as the redis-client
#   `password`. It authenticates every (re)connect with a current token and
#   survives Marshal round-trips (Sidekiq), because it holds only a descriptor
#   and resolves the live provider from {Registry} at call time.
# * {ReauthMiddleware} is a redis-client middleware that re-issues AUTH on a
#   long-lived connection shortly before its token expires.
#
# Usage:
#
#   RedisCloudAuth.register!   # once, at boot
#
#   descriptor = { provider: :azure, resource: "https://redis.azure.com" }
#   RedisClient.config(
#     host: "cache.example.com", port: 10000, ssl: true,
#     username: "<object-id>",
#     password: RedisCloudAuth.credential(descriptor),
#     custom: { credentials_provider: descriptor }
#   )
module RedisCloudAuth
  class Error < StandardError; end

  class << self
    # Logger for re-auth failures (throttled). Defaults to a no-op; consumers
    # (GitLab, mail_room, gitlab-exporter) can inject their own.
    attr_writer :logger

    def logger
      @logger ||= Logger.new(File::NULL)
    end

    # The process-global provider registry.
    def registry
      Registry
    end

    # Convenience: a marshallable callable password for +descriptor+.
    def credential(descriptor)
      TokenCredential.new(descriptor)
    end

    # Register the re-auth middleware with redis-client. Call once at boot.
    # It is a no-op on connections whose config has no credentials_provider
    # descriptor in `custom`.
    def register!
      require "redis-client"
      RedisClient.register(ReauthMiddleware)
    end
  end
end

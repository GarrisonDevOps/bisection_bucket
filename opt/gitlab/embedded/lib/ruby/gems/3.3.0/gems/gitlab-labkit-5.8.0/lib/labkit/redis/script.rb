# frozen_string_literal: true

require "openssl"
require "redis"

module Labkit
  module Redis
    # Wraps a Lua script for EVALSHA-with-NOSCRIPT-fallback execution.
    # The SHA is computed once at construction. Redis caches the script
    # body the first time EVAL is invoked; subsequent EVALSHA calls hit
    # that cache. SCRIPT FLUSH or a Redis restart drops the cache; the
    # NOSCRIPT recovery re-ships the body and re-populates it.
    #
    # @example
    #   SCRIPT = Labkit::Redis::Script.new(<<~LUA)
    #     return redis.call('INCRBY', KEYS[1], ARGV[1])
    #   LUA
    #
    #   pool.with { |conn| SCRIPT.eval(conn, keys: ["counter"], argv: [1]) }
    class Script
      attr_reader :body, :sha

      def initialize(body)
        @body = body.freeze
        # SHA1 is mandated by the Redis EVALSHA wire protocol, not a discretionary hash choice.
        @sha = OpenSSL::Digest::SHA1.hexdigest(body).freeze # rubocop:disable Fips/SHA1
        freeze
      end

      # @param conn a Redis client (the connection checked out of a pool)
      # @param keys [Array] KEYS arguments to the Lua script
      # @param argv [Array] ARGV arguments to the Lua script
      # @return the script's return value
      def eval(conn, keys:, argv:)
        conn.evalsha(@sha, keys: keys, argv: argv)
      # Redis::CommandError and RedisClient::CommandError are sibling class trees
      # with no common ancestor above StandardError -- neither inherits from the
      # other. A NOSCRIPT response arrives as Redis::* on single-instance
      # connections (the redis gem's translator runs) and as RedisClient::* on
      # cluster connections when the cluster translator skips the conversion.
      # Both shapes must reach the EVAL fallback, so we list both classes.
      rescue ::Redis::CommandError, ::RedisClient::CommandError => e
        raise unless e.message.start_with?("NOSCRIPT")

        conn.eval(@body, keys: keys, argv: argv)
      end
    end
  end
end

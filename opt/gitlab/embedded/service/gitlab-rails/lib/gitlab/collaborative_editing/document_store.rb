# frozen_string_literal: true

module Gitlab
  module CollaborativeEditing
    class DocumentStore
      TTL = 1.hour

      COMPACTION_THRESHOLD = 500
      SEED_CLAIM_TTL = 30.seconds
      COMPACTION_CLAIM_TTL = 30.seconds
      MAX_LOG_LENGTH = COMPACTION_THRESHOLD * 4
      MAX_LOG_BYTES = 16.megabytes
      COMPACTION_BYTES = MAX_LOG_BYTES / 2

      FULL = 'full'

      Result = Struct.new(:full, :compaction_token, keyword_init: true) do
        alias_method :full?, :full

        def compact?
          compaction_token.present?
        end
      end

      APPEND_SCRIPT = <<~LUA
        local updates_key, claim_key, bytes_key, snapshot_bytes_key = KEYS[1], KEYS[2], KEYS[3], KEYS[4]
        local update, token = ARGV[1], ARGV[2]
        local ttl, threshold, claim_ttl = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
        local max_length, max_bytes, compact_bytes = tonumber(ARGV[6]), tonumber(ARGV[7]), tonumber(ARGV[8])

        local length = redis.call('llen', updates_key)
        local bytes = tonumber(redis.call('get', bytes_key)) or 0
        local full = length >= max_length or bytes + string.len(update) > max_bytes

        if not full then
          length = redis.call('rpush', updates_key, update)
          bytes = bytes + string.len(update)
          redis.call('expire', updates_key, ttl)
          local expires_at = redis.call('pexpiretime', updates_key)
          redis.call('set', bytes_key, bytes, 'PXAT', expires_at)
          redis.call('pexpireat', snapshot_bytes_key, expires_at)
        end

        local snapshot_bytes = tonumber(redis.call('get', snapshot_bytes_key)) or 0
        local compact_at = math.max(compact_bytes, math.min(snapshot_bytes * 2, (snapshot_bytes + max_bytes) / 2))
        if not full and length < threshold and bytes < compact_at then
          return {}
        end

        if redis.call('set', claim_key, token .. ':' .. length, 'EX', claim_ttl, 'NX') then
          return { full and 'full' or '', token }
        end

        return { full and 'full' or '' }
      LUA

      REPLACE_SCRIPT = <<~LUA
        local updates_key, claim_key, bytes_key, snapshot_bytes_key = KEYS[1], KEYS[2], KEYS[3], KEYS[4]
        local snapshot, token, ttl, max_bytes = ARGV[1], ARGV[2], tonumber(ARGV[3]), tonumber(ARGV[4])

        local claim = redis.call('get', claim_key)
        if not claim then
          return 0
        end

        local claimed_token, claimed_length = string.match(claim, '^(.+):(%d+)$')
        if claimed_token ~= token then
          return 0
        end

        local suffix = redis.call('lrange', updates_key, tonumber(claimed_length), -1)
        local bytes = string.len(snapshot)
        for _, update in ipairs(suffix) do
          bytes = bytes + string.len(update)
        end
        if bytes > max_bytes then
          return -1
        end

        redis.call('ltrim', updates_key, tonumber(claimed_length), -1)
        redis.call('lpush', updates_key, snapshot)
        redis.call('expire', updates_key, ttl)
        local expires_at = redis.call('pexpiretime', updates_key)
        redis.call('set', bytes_key, bytes, 'PXAT', expires_at)
        redis.call('set', snapshot_bytes_key, string.len(snapshot), 'PXAT', expires_at)
        redis.call('del', claim_key)

        return 1
      LUA

      def initialize(document_key)
        @document_key = document_key
      end

      def updates
        with_redis { |redis| redis.lrange(updates_key, 0, -1) }
      end

      def append(update)
        raise ArgumentError, 'update must be a String' unless update.is_a?(String)

        token = SecureRandom.hex(16)

        full, claimed = with_redis do |redis|
          redis.eval(
            APPEND_SCRIPT,
            keys: [updates_key, compaction_key, bytes_key, snapshot_bytes_key],
            argv: [
              update, token, TTL.to_i, COMPACTION_THRESHOLD, COMPACTION_CLAIM_TTL.to_i,
              MAX_LOG_LENGTH, MAX_LOG_BYTES, COMPACTION_BYTES
            ]
          )
        end

        Result.new(full: full == FULL, compaction_token: claimed.presence)
      end

      def replace(snapshot, token)
        raise ArgumentError, 'snapshot must be a String' unless snapshot.is_a?(String)
        raise ArgumentError, 'token must be a String' unless token.is_a?(String)

        return :invalid_claim if token.empty?

        result = with_redis do |redis|
          redis.eval(
            REPLACE_SCRIPT,
            keys: [updates_key, compaction_key, bytes_key, snapshot_bytes_key],
            argv: [snapshot, token, TTL.to_i, MAX_LOG_BYTES]
          )
        end

        { -1 => :full, 0 => :invalid_claim, 1 => :replaced }.fetch(result)
      end

      def claim_seed
        with_redis do |redis|
          redis.set(seed_key, '1', ex: SEED_CLAIM_TTL.to_i, nx: true)
        end
      end

      private

      attr_reader :document_key

      def updates_key
        "collaborative_editing:{#{document_key}}:updates"
      end

      def seed_key
        "collaborative_editing:{#{document_key}}:seed"
      end

      def compaction_key
        "collaborative_editing:{#{document_key}}:compaction"
      end

      def bytes_key
        "collaborative_editing:{#{document_key}}:bytes"
      end

      def snapshot_bytes_key
        "collaborative_editing:{#{document_key}}:snapshot_bytes"
      end

      def with_redis(&block)
        Gitlab::Redis::SharedState.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- Redis client, not ActiveRecord
      end
    end
  end
end

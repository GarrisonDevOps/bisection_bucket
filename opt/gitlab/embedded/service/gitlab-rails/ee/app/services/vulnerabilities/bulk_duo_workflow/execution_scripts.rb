# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class ExecutionScripts
      TERMINAL_STATUS_LUA_GUARD = <<~LUA.freeze
        if current_status == '#{ExecutionState::STATUS_COMPLETED}' or
           current_status == '#{ExecutionState::STATUS_FAILED}' or
           current_status == '#{ExecutionState::STATUS_CANCELLED}' then
          return current_status
        end
      LUA

      CREATE_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA.freeze)
        local metadata_key = KEYS[1]
        local current_key = KEYS[2]
        local latest_key = KEYS[3]

        local ttl = tonumber(ARGV[1])
        local execution_id = ARGV[2]
        local project_id = ARGV[3]
        local workflow = ARGV[4]
        local batch_size = tonumber(ARGV[5])
        local metadata = ARGV[6]
        local stages = ARGV[7]

        local created = redis.call('SET', current_key, execution_id, 'NX', 'EX', ttl)

        if not created then
          return redis.call('GET', current_key)
        end

        redis.call('SET', latest_key, execution_id, 'EX', ttl)

        local now = redis.call('TIME')
        local created_at = string.format("%s.%06d", now[1], tonumber(now[2]))

        redis.call(
          'HSET',
          metadata_key,
          'execution_id', execution_id,
          'project_id', project_id,
          'workflow', workflow,
          'status', '#{ExecutionState::STATUS_CREATED}',
          'created_at', created_at,
          'cancel_requested', 'false',
          'batch_size', batch_size,
          'processed_in_batch', 0,
          'current_stage', 0,
          'metadata', metadata,
          'stages', stages
        )

        redis.call('EXPIRE', metadata_key, ttl)

        return execution_id
      LUA

      START_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA.freeze)
        local metadata_key = KEYS[1]
        local latest_key = KEYS[2]

        local ttl = tonumber(ARGV[1])
        local execution_id = ARGV[2]

        if redis.call('EXISTS', metadata_key) <= 0 then
          return 'not_found'
        end

        local current_status = redis.call('HGET', metadata_key, 'status')

        #{TERMINAL_STATUS_LUA_GUARD}

        if current_status == '#{ExecutionState::STATUS_RUNNING}' then
          return '#{ExecutionState::STATUS_ALREADY_RUNNING}'
        end

        if current_status ~= '#{ExecutionState::STATUS_CREATED}' then
          return 'invalid'
        end

        local now = redis.call('TIME')
        local started_at = string.format("%s.%06d", now[1], tonumber(now[2]))

        redis.call(
          'HSET',
          metadata_key,
          'status', '#{ExecutionState::STATUS_RUNNING}',
          'started_at', started_at,
          'cancel_requested', 'false'
        )

        redis.call('HDEL', metadata_key, 'ended_at')
        redis.call('EXPIRE', metadata_key, ttl)

        if redis.call('GET', latest_key) == execution_id then
          redis.call('EXPIRE', latest_key, ttl)
        end

        return '#{ExecutionState::STATUS_RUNNING}'
      LUA

      TRANSITION_SCRIPT = ::Labkit::Redis::Script.new(<<~LUA.freeze)
        local metadata_key = KEYS[1]
        local current_key = KEYS[2]
        local latest_key = KEYS[3]

        local ttl = tonumber(ARGV[1])
        local execution_id = ARGV[2]
        local next_status = ARGV[3]

        if redis.call('EXISTS', metadata_key) <= 0 then
          return 'not_found'
        end

        local current_status = redis.call('HGET', metadata_key, 'status')

        #{TERMINAL_STATUS_LUA_GUARD}

        local now = redis.call('TIME')
        local ended_at = string.format("%s.%06d", now[1], tonumber(now[2]))

        redis.call(
          'HSET',
          metadata_key,
          'status', next_status,
          'ended_at', ended_at,
          'processed_in_batch', 0
        )

        if next_status == '#{ExecutionState::STATUS_CANCELLED}' then
          redis.call('HSET', metadata_key, 'cancel_requested', 'true')
        end

        if redis.call('GET', current_key) == execution_id then
          redis.call('DEL', current_key)
        end

        redis.call('EXPIRE', metadata_key, ttl)

        if redis.call('GET', latest_key) == execution_id then
          redis.call('EXPIRE', latest_key, ttl)
        end

        return next_status
      LUA

      def initialize(redis:, keys:, ttl:)
        @redis = redis
        @keys = keys
        @ttl = ttl
      end

      def create(execution_id:, project_id:, workflow:, stages:, batch_size:, metadata: {})
        redis.with do |r|
          CREATE_SCRIPT.eval(
            r,
            keys: [keys[:metadata], keys[:current], keys[:latest]],
            argv: [
              ttl.to_i,
              execution_id,
              project_id,
              workflow,
              batch_size,
              metadata.to_json,
              stages.to_json
            ]
          )
        end
      end

      def start(execution_id:)
        redis.with do |r|
          START_SCRIPT.eval(
            r,
            keys: [keys[:metadata], keys[:latest]],
            argv: [ttl.to_i, execution_id]
          )
        end&.to_sym
      end

      def transition(execution_id:, status:)
        redis.with do |r|
          TRANSITION_SCRIPT.eval(
            r,
            keys: [keys[:metadata], keys[:current], keys[:latest]],
            argv: [ttl.to_i, execution_id, status]
          )
        end&.to_sym
      end

      private

      attr_reader :redis, :keys, :ttl
    end
  end
end

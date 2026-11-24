# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SessionCredits
      # Per-root-namespace sync position for the v2 sessions sync. The position is the
      # CustomersDot `updatedAt` watermark in epoch microseconds, stored in ClickHouse
      # `sync_cursors` (0 means unset). The opaque `after` page token lives in Redis,
      # keyed by the window it belongs to, so a job that runs out of time resumes
      # paging where it stopped and a token from an older window is never reused.
      #
      # An unset cursor, or one that fell out of CustomersDot's window while the
      # namespace was quiet, reads from the seed instead: nothing older is retrievable.
      class Cursor
        CURSOR_PREFIX = 'duo_workflow_session_credits_v2_'
        INSTANCE_KEY_SUFFIX = 'instance'
        # The CustomersDot sessions query rejects `updatedAfter` older than 90 days at
        # its own clock, so the seed sits a margin inside that limit.
        SEED_LOOKBACK = 90.days
        SEED_MARGIN = 1.hour
        # A resumed token's window is replayed as-is, so it must still be inside the limit
        # when the job sends it; this margin covers the job's own two-minute runtime.
        TOKEN_WINDOW_MARGIN = 5.minutes
        AFTER_TOKEN_TTL = 7.days
        AFTER_TOKEN_KEY_PREFIX = 'duo_workflow_session_credits_v2:{after}'

        attr_reader :key

        def self.seed_time
          (SEED_LOOKBACK - SEED_MARGIN).ago
        end

        def self.token_window_floor
          (SEED_LOOKBACK - TOKEN_WINDOW_MARGIN).ago
        end

        def initialize(root_namespace_id)
          @key = "#{CURSOR_PREFIX}#{root_namespace_id || INSTANCE_KEY_SUFFIX}"
        end

        def value_us
          @value_us ||= ::ClickHouse::SyncCursor.cursor_for(key).to_i
        end

        # Fixed for the life of the cursor, so every page of a window asks the same
        # updatedAfter. A resumed token brings the window it was issued for with it.
        def updated_after
          @updated_after ||= position_time
        end

        # Where the cursor stands right now: the stored position, or the seed when there
        # is none or it fell out of the window. Not pinned, unlike updated_after.
        def position_time
          value_us == 0 || stale? ? self.class.seed_time : stored_time
        end

        # A stored position CustomersDot would reject; the job reseeds and reports it.
        def stale?
          value_us != 0 && stored_time <= self.class.seed_time
        end

        # True when this run reads from the seed rather than from a stored position or a
        # resumable token. Read after #after_token, which is what detects the token case;
        # a dropped token costs nothing when earlier ticks already advanced the cursor.
        def reseeded?
          stale? || (@token_window_expired == true && value_us == 0)
        end

        def stored_time
          Time.zone.at(Rational(value_us, 1_000_000))
        end

        # Moves the position without touching the pinned window: a drain advances after
        # every written buffer while its pages keep asking the same updatedAfter.
        def advance!(micros)
          ::ClickHouse::SyncCursor.update_cursor_for(key, micros)
          @value_us = micros
        end

        # One token per cursor, not per window: the window travels inside the token, and
        # the cursor may advance while the token is still live.
        def after_token_key
          "#{AFTER_TOKEN_KEY_PREFIX}:#{key}"
        end

        def after_token
          raw = Gitlab::Redis::SharedState.with { |redis| redis.get(after_token_key) }
          return unless raw

          data = Gitlab::Json::SafeParser.parse(raw)
          return data['c'].presence unless data['u']

          window = Time.zone.at(Rational(data['u'].to_i, 1_000_000))

          # The token pins a window CustomersDot is about to reject (the token lives a
          # week, the limit does not move). Replaying it would fail every tick, so drop it
          # and reseed instead.
          if window <= self.class.token_window_floor
            clear_after_token
            @token_window_expired = true
            return
          end

          @updated_after = window
          data['c'].presence
        rescue JSON::ParserError
          nil
        end

        # Stored with the window it belongs to: the seed moves with the clock, and a
        # token must be replayed against the exact updatedAfter it was issued for.
        def store_after_token(token)
          payload = Gitlab::Json.dump({ c: token, u: (updated_after.to_r * 1_000_000).to_i })
          Gitlab::Redis::SharedState.with { |redis| redis.set(after_token_key, payload, ex: AFTER_TOKEN_TTL.to_i) }
        end

        def clear_after_token
          Gitlab::Redis::SharedState.with { |redis| redis.del(after_token_key) }
        end
      end
    end
  end
end

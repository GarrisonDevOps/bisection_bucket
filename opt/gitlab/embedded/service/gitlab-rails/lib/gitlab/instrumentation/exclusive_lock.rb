# frozen_string_literal: true

module Gitlab
  module Instrumentation
    class ExclusiveLock
      extend RequestStoreCounters

      EXCLUSIVE_LOCK_REQUESTED_COUNT = :exclusive_lock_requested_count
      EXCLUSIVE_LOCK_WAIT_DURATION = :exclusive_lock_wait_duration_s
      EXCLUSIVE_LOCK_HOLD_DURATION = :exclusive_lock_hold_duration_s

      class << self
        def requested_count
          counter_value(EXCLUSIVE_LOCK_REQUESTED_COUNT)
        end

        def increment_requested_count
          increment_counter(EXCLUSIVE_LOCK_REQUESTED_COUNT)
        end

        def wait_duration
          counter_value(EXCLUSIVE_LOCK_WAIT_DURATION)
        end

        def add_wait_duration(duration)
          increment_counter(EXCLUSIVE_LOCK_WAIT_DURATION, duration)
        end

        def hold_duration
          counter_value(EXCLUSIVE_LOCK_HOLD_DURATION)
        end

        def add_hold_duration(duration)
          increment_counter(EXCLUSIVE_LOCK_HOLD_DURATION, duration)
        end
      end

      def self.payload
        {
          EXCLUSIVE_LOCK_REQUESTED_COUNT => requested_count,
          EXCLUSIVE_LOCK_WAIT_DURATION => wait_duration,
          EXCLUSIVE_LOCK_HOLD_DURATION => hold_duration
        }
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Instrumentation
    # Per-request counters kept in Gitlab::SafeRequestStore under the key the
    # caller passes. Reads default to 0 and increments are dropped when the
    # store is inactive, so cron and rake callers never see nil arithmetic.
    module RequestStoreCounters
      def increment_counter(key, amount = 1)
        return unless ::Gitlab::SafeRequestStore.active?

        ::Gitlab::SafeRequestStore[key] = counter_value(key) + amount
      end

      def counter_value(key)
        ::Gitlab::SafeRequestStore[key] || 0
      end

      def counter_duration(key)
        counter_value(key).round(::Gitlab::InstrumentationHelper::DURATION_PRECISION)
      end
    end
  end
end

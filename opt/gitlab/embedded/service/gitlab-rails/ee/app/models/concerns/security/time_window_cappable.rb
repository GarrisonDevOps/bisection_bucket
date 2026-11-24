# frozen_string_literal: true

# Provides `effective_time_window` which caps the configured time_window
# to not exceed the interval until the next scheduled run.
#
# Includers must implement:
# - `calculate_next_run_at`
# - `time_window_seconds`
module Security
  module TimeWindowCappable
    extend ActiveSupport::Concern

    def effective_time_window(next_run_at = nil, defer_cap: false)
      return unless time_window_seconds

      now = Time.zone.now
      next_run_at ||= calculate_next_run_at(now)

      if defer_cap
        # Cap against the SECOND cron occurrence.
        second_occurrence = calculate_next_run_at(next_run_at)
        seconds_until_cap = [(second_occurrence - next_run_at).to_i, 0].max
      else
        seconds_until_cap = [(next_run_at - now).to_i, 0].max
      end

      [time_window_seconds, seconds_until_cap].min
    end
  end
end

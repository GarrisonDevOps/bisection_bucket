# frozen_string_literal: true

# Provides cron-based scheduling with a randomized delay within a capped time window.
# Used for scan execution policy and pipeline execution policy schedules.
module Security
  module CronSchedulableWithDelay
    extend ActiveSupport::Concern
    include Security::TimeWindowCappable

    def schedule_next_run!
      set_next_run_at
      save!
    end

    private

    def set_next_run_at
      self.next_run_at = calculate_next_run_at

      # For new records, defer the cap to allow the full time_window on the first run.
      capped_window = effective_time_window(next_run_at, defer_cap: new_record?)
      delay = capped_window&.positive? ? Random.rand(capped_window) : 0
      self.next_run_at += delay.seconds
      self.next_run_applied_delay = delay
    end

    def calculate_next_run_at(from_time = Time.zone.now)
      Gitlab::Ci::CronParser
        .new(cron, cron_timezone)
        .next_time_from(from_time)
    end
  end
end

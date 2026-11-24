# frozen_string_literal: true

module Gitlab
  module Security
    module Orchestration
      module PipelineExecutionPolicies
        module Intervals
          UnsupportedScheduleTypeError = Class.new(StandardError)

          Interval = Data.define(:cron, :time_window, :time_zone, :snoozed_until)

          DEFAULT_TIMEZONE = "UTC"
          CRON_DAY_MAP = {
            "Sunday" => 0,
            "Monday" => 1,
            "Tuesday" => 2,
            "Wednesday" => 3,
            "Thursday" => 4,
            "Friday" => 5,
            "Saturday" => 6
          }.freeze

          module_function

          def from_schedules(schedules)
            schedules.map do |schedule|
              snooze_value = schedule.dig("snooze", "until")
              snoozed_until = Time.zone.parse(snooze_value) if snooze_value

              Interval.new(
                cron: crontab(schedule),
                time_window: schedule.dig("time_window", "value"),
                time_zone: schedule.fetch("timezone", DEFAULT_TIMEZONE),
                snoozed_until: snoozed_until
              )
            end
          end

          def crontab(schedule)
            case schedule["type"]
            when "daily"
              daily_crontab(schedule)
            when "weekly"
              weekly_crontab(schedule)
            when "monthly"
              monthly_crontab(schedule)
            else
              raise UnsupportedScheduleTypeError, "#{schedule} is not a supported schedule type"
            end
          end

          def daily_crontab(schedule)
            build_crontab(schedule)
          end

          def weekly_crontab(schedule)
            days_of_week = schedule["days"].to_a.filter_map { |day| CRON_DAY_MAP.fetch(day) }.join(",")
            days_of_week = '0' if days_of_week.empty?
            build_crontab(schedule, days_of_week: days_of_week)
          end

          def monthly_crontab(schedule)
            days = schedule["days_of_month"].to_a.join(",")
            days = '1' if days.empty?
            build_crontab(schedule, days: days)
          end

          def build_crontab(schedule, days: '*', days_of_week: '*')
            hour, minute = parse_hours_minutes(schedule["start_time"])
            "#{minute} #{hour} #{days} * #{days_of_week}"
          end

          def parse_hours_minutes(hhmm)
            return [0, 0] if hhmm.blank?

            hhmm.split(":").map(&:to_i)
          end
        end
      end
    end
  end
end

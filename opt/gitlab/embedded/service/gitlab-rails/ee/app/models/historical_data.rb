# frozen_string_literal: true

class HistoricalData < ApplicationRecord
  validates :recorded_at, presence: true

  # HistoricalData.during((Time.current - 1.year)..Time.current).average(:active_user_count)
  scope :during, ->(range) { where(recorded_at: range) }

  # Seat link exports are keyed on the UTC calendar day, matching how usage_date is written
  # on billable_usage_daily_aggregates. recorded_at is a timestamptz, so the cast names the
  # zone; otherwise the session zone decides which day a row belongs to.
  RECORDED_ON_UTC_SQL = "(recorded_at AT TIME ZONE 'UTC')::date"

  scope :daily_maximums_on_utc_dates, ->(date_range) do
    select(Arel.sql("#{RECORDED_ON_UTC_SQL} AS recorded_on, MAX(active_user_count) AS active_user_count"))
      .where(recorded_at: date_range.begin.to_time(:utc)...(date_range.end + 1).to_time(:utc))
      .group(Arel.sql(RECORDED_ON_UTC_SQL))
      .order(Arel.sql(RECORDED_ON_UTC_SQL))
  end

  class << self
    def track!
      create!(
        recorded_at: Time.current,
        active_user_count: License.load_license&.daily_billable_users_count
      )
    end

    def max_historical_user_count(from:, to:)
      HistoricalData.during(from..to).maximum(:active_user_count) || 0
    end
  end
end

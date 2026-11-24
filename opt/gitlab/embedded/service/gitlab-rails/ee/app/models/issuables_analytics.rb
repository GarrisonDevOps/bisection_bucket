# frozen_string_literal: true

# Gather the number of issuables created by month returning
# a hash with the format: {"2017-12"=>2, "2018-01"=>2, "2018-03"=>1}
#
# By default it creates the hash only for the last 12 months including the current month, but it accepts
# a parameter to get issuables for n months back.
class IssuablesAnalytics
  include Gitlab::Utils::StrongMemoize

  attr_reader :issuables, :start_date, :end_date, :months_back

  DATE_FORMAT = "%Y-%m"

  def initialize(issuables:, months_back: nil, actor: nil)
    @issuables = issuables
    @actor = actor
    @months_back = months_back.to_i - 1 if months_back.present?
    @months_back ||= 12
    @start_date = @months_back.months.ago.beginning_of_month.to_date
    @end_date = Date.today
  end

  def data
    return data_from_created_at_dates unless Feature.enabled?(:issues_analytics_sql_aggregation, actor)

    months_in_range.index_with { |month| created_counts_by_month.fetch(month, 0) }
  end

  private

  attr_reader :actor

  def months_in_range
    month_count = ((end_date.year - start_date.year) * 12) + end_date.month - start_date.month

    (0..month_count).map { |offset| (start_date >> offset).strftime(DATE_FORMAT) }
  end

  # issues.created_at is a UTC timestamp without time zone. Read it as UTC, then format the month in
  # Time.zone, the same zone the strftime in the legacy path uses.
  def created_counts_by_month
    strong_memoize(:created_counts_by_month) do
      month_sql = ApplicationRecord.sanitize_sql_array(
        ["to_char(issues.created_at AT TIME ZONE 'UTC' AT TIME ZONE ?, 'YYYY-MM')", Time.zone.tzinfo.name]
      )

      issuables
        .without_order
        .unscope(:select, :group)
        .where('issues.created_at >= ?', months_back.months.ago.beginning_of_month)
        .group(Arel.sql(month_sql))
        .count
    end
  end

  def data_from_created_at_dates
    start_date.upto(end_date).each_with_object({}) do |date, data_hash|
      date = date.strftime(DATE_FORMAT)
      data_hash[date] = issues_created_at_dates.count(date) || 0
    end
  end

  def issues_created_at_dates
    strong_memoize(:issues_created_at_dates) do
      issuables
        .without_order
        .where('issues.created_at >= ?', months_back.months.ago.beginning_of_month)
        .pluck('issues.created_at')
        .map { |date| date.strftime(DATE_FORMAT) }
    end
  end
end

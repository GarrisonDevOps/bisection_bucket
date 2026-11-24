# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      # Builds the `coverage` block of an air-gapped usage export, claiming only what each
      # dataset can prove. Seat link is recorded daily regardless of usage, so a missing
      # day means nothing was recorded. A usage row exists only once an event happens, so
      # for billable events a missing day proves nothing and only the count is reported.
      class Coverage
        # The period comes from the series, so this block always covers the same days as the
        # exported seat link records. billable_events_dates are the dates of the exported
        # billable events records, so the count describes exactly what the export holds.
        def initialize(seat_link_series:, billable_events_dates:)
          @seat_link_series = seat_link_series
          @billable_events_dates = billable_events_dates
        end

        def to_h
          return empty_result if empty_period?

          {
            period_days: period_days,
            seat_link: seat_link_coverage(seat_link_series.dates),
            billable_events: billable_events_coverage((all_dates & billable_events_dates).size)
          }
        end

        private

        attr_reader :seat_link_series, :billable_events_dates

        delegate :period_start, :period_end, to: :seat_link_series, private: true

        def empty_period?
          period_start > period_end
        end

        def period_days
          all_dates.size
        end

        def all_dates
          @all_dates ||= (period_start..period_end).to_a
        end

        def seat_link_coverage(dates_with_data)
          days_with_data = dates_with_data.size
          no_data_dates = (all_dates - dates_with_data).map(&:iso8601)

          {
            included: true,
            expected_days: period_days,
            days_with_data: days_with_data,
            complete: days_with_data == period_days,
            no_data_dates: no_data_dates
          }
        end

        def billable_events_coverage(days_with_data)
          { included: true, days_with_data: days_with_data }
        end

        def empty_result
          {
            period_days: 0,
            seat_link: seat_link_coverage([]),
            billable_events: billable_events_coverage(0)
          }
        end
      end
    end
  end
end

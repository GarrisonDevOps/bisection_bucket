# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class Period
        LATE_ARRIVAL_GRACE_DAYS = 0

        def self.for_license(license)
          term_end = license.expires_at&.prev_day

          new(start_date: license.starts_at.to_date, end_date: [last_completed_day, term_end].compact.min)
        end

        # usage_date is written as a UTC date, so Date.current would export a
        # still-open day on any instance east of UTC.
        def self.last_completed_day
          Time.current.utc.to_date - 1 - LATE_ARRIVAL_GRACE_DAYS
        end

        attr_reader :start_date, :end_date

        def initialize(start_date:, end_date:)
          @start_date = start_date
          @end_date = end_date
        end

        def range
          start_date..end_date
        end

        def empty?
          start_date > end_date
        end
      end
    end
  end
end

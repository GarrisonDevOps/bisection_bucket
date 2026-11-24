# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class UsageRecordsService
        def initialize(period)
          @period = period
        end

        def execute
          UsageRecordEntity.represent(rows).as_json
        end

        private

        attr_reader :period

        def rows
          DailyTotal
            .in_period(period)
            .ordered_for_export
        end
      end
    end
  end
end

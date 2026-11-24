# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class Term
        LIMIT = 2

        def self.available
          License.history
            .select(&:started?)
            .reject(&:trial?)
            .uniq(&:starts_at)
            .first(LIMIT)
            .map { |license| new(license) }
        end

        def self.find(license_id)
          available.find { |term| term.license.id == license_id.to_i }
        end

        def self.current
          available.find(&:current?)
        end

        attr_reader :license

        delegate :seats, to: :license

        def initialize(license)
          @license = license
        end

        def period
          @period ||= Period.for_license(license)
        end

        def current?
          license.starts_at == License.current&.starts_at
        end

        def end_date
          license.expires_at&.prev_day
        end

        def last_exported_at
          ExportLog.last_generated_at_for(period_start: period.start_date)
        end
      end
    end
  end
end

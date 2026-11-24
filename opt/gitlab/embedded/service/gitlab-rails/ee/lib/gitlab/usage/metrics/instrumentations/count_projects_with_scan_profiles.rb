# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithScanProfiles < DatabaseMetric
          operation :distinct_count, column: 'project_id'

          relation { ::Security::ScanProfileProject }

          def initialize(metric_definition)
            super

            return if scan_type

            raise ArgumentError, "scan_type must be present and one of: #{scan_types.join(', ')}"
          end

          private

          def relation
            super
              .joins(:scan_profile)
              .where(security_scan_profiles: { scan_type: scan_type })
          end

          def scan_type
            Enums::Security.security_profile_types[options[:scan_type]&.to_sym]
          end

          def scan_types
            Enums::Security.security_profile_types.keys
          end
        end
      end
    end
  end
end

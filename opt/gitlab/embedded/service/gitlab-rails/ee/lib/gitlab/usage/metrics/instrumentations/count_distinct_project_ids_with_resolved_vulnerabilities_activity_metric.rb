# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctProjectIdsWithResolvedVulnerabilitiesActivityMetric < DatabaseMetric
          INVALID_REPORT_TYPE_ERROR = "option 'report_type' must be valid enum"

          operation :distinct_count, column: :project_id

          timestamp_column('vulnerability_state_transitions.created_at')

          def initialize(metric_definition)
            super

            raise ArgumentError, INVALID_REPORT_TYPE_ERROR unless valid_report_type?(options[:report_type])
          end

          # We must override value since we are not able to batch this query due to usage of the count subquery
          def value
            relation.distinct.count(:project_id)
          end

          def relation
            Vulnerabilities::Read.joins(
              <<-SQL
                INNER JOIN vulnerability_state_transitions
                  ON vulnerability_state_transitions.vulnerability_id = vulnerability_reads.vulnerability_id
              SQL
            ).where(
              vulnerability_state_transitions: { to_state: Enums::Vulnerability::VULNERABILITY_STATES[:resolved] },
              report_type: options[:report_type]
            ).where(time_constraints)
          end

          def valid_report_type?(report_type)
            Enums::Vulnerability.report_types.key?(report_type.to_sym)
          end
        end
      end
    end
  end
end

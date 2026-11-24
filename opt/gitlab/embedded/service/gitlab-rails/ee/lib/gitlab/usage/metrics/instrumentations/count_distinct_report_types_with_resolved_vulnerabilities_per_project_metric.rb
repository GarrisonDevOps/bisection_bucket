# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctReportTypesWithResolvedVulnerabilitiesPerProjectMetric < DatabaseMetric
          operation :count

          timestamp_column('vulnerability_state_transitions.created_at')

          # Override sql so that it doesn't use the Vulnerabilities::Read table name
          def to_sql
            relation.select("COUNT(*)").to_sql
          end

          # We must override value since we are not able to batch this query due to usage of the count subquery
          def value
            relation.count
          end

          def relation
            base_relation = Vulnerabilities::Read.joins(
              <<-SQL
                INNER JOIN vulnerability_state_transitions
                  ON vulnerability_state_transitions.vulnerability_id = vulnerability_reads.vulnerability_id
              SQL
            ).where(
              vulnerability_state_transitions: { to_state: Enums::Vulnerability::VULNERABILITY_STATES[:resolved] }
            ).where(time_constraints).group(
              :project_id,
              :report_type
            ).distinct.select(
              :project_id,
              :report_type
            )

            Vulnerabilities::Read.from(base_relation)
          end
        end
      end
    end
  end
end

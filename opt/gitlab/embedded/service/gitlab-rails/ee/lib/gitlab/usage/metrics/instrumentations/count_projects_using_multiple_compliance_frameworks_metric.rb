# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsUsingMultipleComplianceFrameworksMetric < DatabaseMetric
          operation :distinct_count, column: :project_id

          relation do
            ::ComplianceManagement::ComplianceFramework::ProjectSettings
              .joins("INNER JOIN (
                SELECT project_id
                FROM project_compliance_framework_settings
                GROUP BY project_id
                HAVING COUNT(*) > 1
              ) settings ON project_compliance_framework_settings.project_id = settings.project_id"
                    )
          end
        end
      end
    end
  end
end

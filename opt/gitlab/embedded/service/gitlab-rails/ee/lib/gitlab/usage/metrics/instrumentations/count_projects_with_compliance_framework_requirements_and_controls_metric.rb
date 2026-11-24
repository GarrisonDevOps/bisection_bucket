# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithComplianceFrameworkRequirementsAndControlsMetric < DatabaseMetric
          operation :distinct_count, column: 'projects.id'

          relation do
            ::Project
              .joins(compliance_management_frameworks: { compliance_requirements: :compliance_requirements_controls })
          end

          start { ::Project.minimum(:id) }
          finish { ::Project.maximum(:id) }

          timestamp_column 'projects.created_at'
        end
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountFrameworksWithRequirementsMetric < DatabaseMetric
          operation :distinct_count, column: 'compliance_management_frameworks.id'

          relation do
            ::ComplianceManagement::Framework
              .joins(:compliance_requirements)
          end

          start { ::ComplianceManagement::Framework.minimum(:id) }
          finish { ::ComplianceManagement::Framework.maximum(:id) }
        end
      end
    end
  end
end

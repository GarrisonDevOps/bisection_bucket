# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountComplianceFrameworksMetric < DatabaseMetric
          operation :count

          relation do
            ::ComplianceManagement::Framework
          end
        end
      end
    end
  end
end

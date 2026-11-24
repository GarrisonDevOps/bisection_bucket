# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithValidityChecksEnabledMetric < DatabaseMetric
          operation :count

          relation do
            ProjectSecuritySetting.where(validity_checks_enabled: true)
          end
        end
      end
    end
  end
end

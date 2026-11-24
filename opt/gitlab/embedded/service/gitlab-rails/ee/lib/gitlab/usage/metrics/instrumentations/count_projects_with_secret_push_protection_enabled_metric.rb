# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithSecretPushProtectionEnabledMetric < DatabaseMetric
          operation :count

          relation do
            ProjectSecuritySetting.where(secret_push_protection_enabled: true)
          end
        end
      end
    end
  end
end

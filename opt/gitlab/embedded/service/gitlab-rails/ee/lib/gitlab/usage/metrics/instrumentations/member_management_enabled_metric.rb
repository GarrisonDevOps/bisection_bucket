# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class MemberManagementEnabledMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.enable_member_promotion_management?
          end
        end
      end
    end
  end
end

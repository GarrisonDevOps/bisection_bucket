# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class SastGroupWorker < GroupBaseWorker
        data_consistency :delayed
        idempotent!
        urgency :low

        feature_category :compliance_management
        def worker_class
          ::ComplianceManagement::Standards::Gitlab::SastWorker
        end
      end
    end
  end
end

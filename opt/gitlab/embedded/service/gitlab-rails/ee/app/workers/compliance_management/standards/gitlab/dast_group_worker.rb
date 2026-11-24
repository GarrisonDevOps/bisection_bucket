# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class DastGroupWorker < GroupBaseWorker
        data_consistency :delayed
        idempotent!
        urgency :low

        feature_category :compliance_management
        def worker_class
          ::ComplianceManagement::Standards::Gitlab::DastWorker
        end
      end
    end
  end
end

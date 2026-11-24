# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Gitlab
      class AtLeastTwoApprovalsGroupWorker < GroupBaseWorker
        data_consistency :sticky
        idempotent!
        urgency :low

        feature_category :compliance_management

        def worker_class
          ComplianceManagement::Standards::Gitlab::AtLeastTwoApprovalsWorker
        end
      end
    end
  end
end

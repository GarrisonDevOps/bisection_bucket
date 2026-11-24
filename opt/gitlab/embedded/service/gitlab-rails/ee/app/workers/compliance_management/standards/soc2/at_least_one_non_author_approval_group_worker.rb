# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Soc2
      class AtLeastOneNonAuthorApprovalGroupWorker < GroupBaseWorker
        data_consistency :sticky
        idempotent!
        urgency :low

        feature_category :compliance_management

        def worker_class
          ::ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalWorker
        end
      end
    end
  end
end

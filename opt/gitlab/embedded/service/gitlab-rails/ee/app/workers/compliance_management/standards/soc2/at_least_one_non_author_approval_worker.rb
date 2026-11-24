# frozen_string_literal: true

module ComplianceManagement
  module Standards
    module Soc2
      class AtLeastOneNonAuthorApprovalWorker < BaseWorker
        data_consistency :sticky
        idempotent!
        urgency :low

        feature_category :compliance_management

        def service_class
          ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalService
        end
      end
    end
  end
end

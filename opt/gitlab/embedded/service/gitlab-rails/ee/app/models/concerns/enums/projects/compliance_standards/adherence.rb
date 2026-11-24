# frozen_string_literal: true

module Enums
  module Projects
    module ComplianceStandards
      module Adherence
        def self.status
          { success: 0, fail: 1 }.freeze
        end

        def self.check_name
          {
            ::ComplianceManagement::Standards::Gitlab::PreventApprovalByAuthorService::CHECK_NAME => 0,
            ::ComplianceManagement::Standards::Gitlab::PreventApprovalByCommitterService::CHECK_NAME => 1,
            ::ComplianceManagement::Standards::Gitlab::AtLeastTwoApprovalsService::CHECK_NAME => 2,
            ::ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalService::CHECK_NAME => 3,
            ::ComplianceManagement::Standards::Gitlab::SastService::CHECK_NAME => 4,
            ::ComplianceManagement::Standards::Gitlab::DastService::CHECK_NAME => 5
          }
        end

        def self.standard
          {
            ::ComplianceManagement::Standards::Gitlab::BaseService::STANDARD => 0,
            ::ComplianceManagement::Standards::Soc2::BaseService::STANDARD => 1
          }
        end
      end
    end
  end
end

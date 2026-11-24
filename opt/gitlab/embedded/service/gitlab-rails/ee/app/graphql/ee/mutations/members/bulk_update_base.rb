# frozen_string_literal: true

module EE
  module Mutations
    module Members
      module BulkUpdateBase
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          field :queued_member_approvals,
            EE::Types::GitlabSubscriptions::MemberManagement::MemberApprovalType.connection_type,
            null: true,
            description: 'List of queued pending members approvals.'
        end

        private

        override :present_result
        def present_result(result)
          super.merge(
            queued_member_approvals: result[:queued_member_approvals]
          )
        end
      end
    end
  end
end

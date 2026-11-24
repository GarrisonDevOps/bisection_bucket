# frozen_string_literal: true

module Mutations
  module GitlabSubscriptions
    module MemberManagement
      class ProcessUserBillablePromotionRequest < BaseMutation
        graphql_name 'ProcessUserBillablePromotionRequest'

        authorize_granular_token permissions: :update_member_approval, boundary: :instance,
          boundary_type: :instance,
          assignable_when: [:admin, :self_managed]

        include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

        argument :user_id, ::Types::GlobalIDType[::User],
          required: true, description: 'Global ID of user to be promoted.'

        argument :status, EE::Types::GitlabSubscriptions::MemberManagement::MemberApprovalStatusEnum,
          required: true,
          description: 'Status for the member approval request (approved, denied, pending).'

        field :result, EE::Types::GitlabSubscriptions::MemberManagement::UserPromotionStatusEnum,
          null: true,
          description: 'Status of the user promotion process (success, partial_success, failed).'

        def resolve(user_id:, status:)
          raise_resource_not_available_error! unless
            member_promotion_management_enabled? && current_user.can_admin_all_resources?

          user = Gitlab::Graphql::Lazy.force(GitlabSchema.find_by_gid(user_id))

          result = ::GitlabSubscriptions::MemberManagement::ProcessUserBillablePromotionService
                       .new(user, current_user, { status: status }).execute

          { result: result.payload[:result], errors: result.errors }
        end
      end
    end
  end
end

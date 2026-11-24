# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    module MemberManagement
      module SelfManaged
        class UsersQueuedForRolePromotionResolver < BaseResolver
          include Gitlab::Graphql::Authorize::AuthorizeResource
          include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

          type EE::Types::GitlabSubscriptions::MemberManagement::
              UsersQueuedForRolePromotionType.connection_type, null: true

          def resolve
            authorize!

            ::GitlabSubscriptions::MemberManagement::SelfManaged::MaxAccessLevelMemberApprovalsFinder.new(current_user)
                                                                                                    .execute
          end

          def authorize!
            raise_resource_not_available_error! unless member_promotion_management_enabled? &&
              current_user.can_admin_all_resources?
          end
        end
      end
    end
  end
end

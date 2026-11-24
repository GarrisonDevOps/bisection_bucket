# frozen_string_literal: true

module Resolvers
  module GitlabSubscriptions
    module MemberManagement
      class MemberApprovalResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

        type EE::Types::GitlabSubscriptions::MemberManagement::MemberApprovalType.connection_type, null: true

        def resolve
          return unless authorize!

          ::GitlabSubscriptions::MemberManagement::MemberApprovalFinder.new(
            current_user: current_user,
            source: object
          ).execute
        end

        def authorize!
          return false unless member_promotion_management_enabled?

          case object
          when ::Group
            Ability.allowed?(current_user, :admin_group_member, object)
          when ::Project
            Ability.allowed?(current_user, :admin_project_member, object)
          else
            raise_resource_not_available_error!
          end
        end
      end
    end
  end
end

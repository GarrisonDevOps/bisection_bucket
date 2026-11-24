# frozen_string_literal: true

module Preloaders
  class UserMemberRolesForAdminPreloader
    include Gitlab::Utils::StrongMemoize

    attr_reader :user

    def initialize(user:)
      @user = user
    end

    def execute
      ::Gitlab::SafeRequestLoader.execute(
        resource_key: resource_key,
        resource_ids: [:admin]
      ) do
        admin_abilities_for_user
      end
    end

    private

    def admin_abilities_for_user
      return { admin: [] } unless custom_roles_enabled?

      user_abilities = if Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
                         Authz::UserAdminRole.where(user_id: user.id).includes(:admin_role).flat_map do |user_role|
                           user_role.admin_role.enabled_permissions.keys
                         end
                       else
                         Users::UserMemberRole.where(user_id: user.id).includes(:member_role).flat_map do |user_role|
                           user_role.member_role.enabled_admin_permissions.keys
                         end
                       end

      { admin: user_abilities }
    end

    def custom_roles_enabled?
      ::License.feature_available?(:custom_roles)
    end

    def resource_key
      "member_roles_for_admin:user:#{user.id}"
    end
  end
end

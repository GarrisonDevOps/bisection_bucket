# frozen_string_literal: true

module Members
  class MemberRolePolicy < BasePolicy
    delegate { @subject.namespace }

    condition(:custom_roles_allowed) do
      ::License.feature_available?(:custom_roles)
    end

    condition(:is_instance_member_role, scope: :subject) do
      @subject.namespace.nil?
    end

    rule { is_instance_member_role & custom_roles_allowed }.policy do
      enable :read_member_role
    end

    rule { admin & custom_roles_allowed }.policy do
      enable :admin_member_role
      enable :read_member_role
      enable :read_admin_role
      enable :update_admin_role
      enable :delete_admin_role
    end
  end
end

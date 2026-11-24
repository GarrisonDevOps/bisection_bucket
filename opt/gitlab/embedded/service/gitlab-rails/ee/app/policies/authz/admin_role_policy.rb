# frozen_string_literal: true

module Authz
  class AdminRolePolicy < BasePolicy
    condition(:custom_roles_allowed) do
      ::License.feature_available?(:custom_roles)
    end

    rule { admin & custom_roles_allowed }.policy do
      enable :read_admin_role
      enable :update_admin_role
      enable :delete_admin_role
    end
  end
end

# frozen_string_literal: true

module VirtualRegistries
  module Policies
    class GroupPolicy < ::BasePolicy
      delegate(:group) { @subject.group }

      condition(:deploy_token_user, scope: :user, score: 0) { @user.is_a?(DeployToken) }

      condition(:deploy_token_can_read_virtual_registry, score: 10) do
        @user.read_virtual_registry && @user.has_access_to_group?(@subject.group)
      end

      rule { anonymous | group.has_parent }.policy do
        prevent :read_virtual_registry
        prevent :create_virtual_registry
        prevent :update_virtual_registry
        prevent :admin_virtual_registry
        prevent :destroy_virtual_registry
        prevent :read_virtual_registry_setting
        prevent :update_virtual_registry_setting
        prevent :create_virtual_registry_cleanup_policy
        prevent :read_virtual_registry_cleanup_policy
        prevent :update_virtual_registry_cleanup_policy
        prevent :delete_virtual_registry_cleanup_policy
      end

      rule { deploy_token_user & deploy_token_can_read_virtual_registry }.policy do
        enable :read_virtual_registry
      end

      rule { deploy_token_user & ~deploy_token_can_read_virtual_registry }.policy do
        prevent :read_virtual_registry
      end
    end
  end
end

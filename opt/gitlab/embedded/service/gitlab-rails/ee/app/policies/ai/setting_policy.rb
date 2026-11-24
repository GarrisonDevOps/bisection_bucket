# frozen_string_literal: true

module Ai
  class SettingPolicy < BasePolicy
    condition(:allowed_to_read_self_hosted_models_settings) do
      can?(:manage_self_hosted_models_settings, :global)
    end

    condition(:allowed_to_update_duo_core_setting) do
      can?(:update_duo_core_setting, :global)
    end

    condition(:allowed_to_update_ai_gateway_timeout) do
      can?(:update_ai_gateway_timeout, :global)
    end

    rule { allowed_to_read_self_hosted_models_settings }.policy do
      enable :read_self_hosted_models_settings
    end

    rule { allowed_to_update_ai_gateway_timeout }.policy do
      enable :read_ai_gateway_timeout
    end

    rule { allowed_to_update_duo_core_setting }.policy do
      enable :read_duo_core_settings
      enable :update_ai_role_based_permission_settings
      enable :read_ai_role_based_permission_settings
    end
  end
end

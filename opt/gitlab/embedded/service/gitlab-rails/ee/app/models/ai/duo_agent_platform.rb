# frozen_string_literal: true

module Ai
  module DuoAgentPlatform
    module_function

    def configured?(user:, container:)
      return false unless container.duo_features_enabled

      feature_setting = ::Ai::FeatureSettingSelectionService.new(
        user, :duo_agent_platform, container.root_ancestor
      ).execute.payload

      # SaaS customers always have DWS available
      # Self-managed instances without a feature_setting record also default to cloud-connected models
      #
      # Only self-managed instances with self_hosted? == true need further validation
      return true unless feature_setting&.self_hosted?

      # Self-hosted customers need compatible model and DWS configured
      return false if feature_setting.self_hosted_model&.unsupported_family_for_duo_agent_platform_code_review?

      ::Gitlab::DuoWorkflow::Client.self_hosted_url.present?
    end

    def available?(user:, container:)
      configured?(user:, container:) &&
        user.allowed_to_use?(:duo_agent_platform, root_namespace: container.root_ancestor)
    end
  end
end

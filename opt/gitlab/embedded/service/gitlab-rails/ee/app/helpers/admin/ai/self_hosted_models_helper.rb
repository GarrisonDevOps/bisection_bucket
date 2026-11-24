# frozen_string_literal: true

module Admin
  module Ai
    module SelfHostedModelsHelper
      MODEL_NAME_MAPPER = {
        "mistral" => "Mistral",
        "mixtral" => "Mixtral",
        "llama3" => "Llama 3",
        "codegemma" => "CodeGemma",
        "codestral" => "Mistral Codestral",
        "codellama" => "Code Llama",
        "deepseekcoder" => "DeepSeek Coder",
        "claude_3" => "Claude",
        "gpt" => "GPT",
        "gemini" => "Gemini",
        "general" => "General",
        "embedding" => "Embedding",
        "qwen" => "Qwen"
      }.freeze

      def model_choices_as_options
        model_options =
          ::Ai::SelfHostedModel.models.filter_map do |name, _|
            release_state = ::Ai::SelfHostedModel::MODELS_RELEASE_STATE[name.to_sym]

            next if release_state == ::Ai::SelfHostedModel::RELEASE_STATE_BETA && !beta_models_enabled?

            {
              modelValue: name.upcase,
              modelName: MODEL_NAME_MAPPER[name] || name.humanize,
              releaseState: release_state
            }
          end

        model_options.sort_by { |option| option[:modelName] }
      end

      def dedicated_instance?
        ::Gitlab::Dedicated.feature_available?(:self_hosted_models)
      end

      def can_manage_instance_model_selection?
        ::Ability.allowed?(current_user, :manage_instance_model_selection)
      end

      def can_manage_self_hosted_models?
        ::Ability.allowed?(current_user, :manage_self_hosted_models_settings)
      end

      def can_manage_dap_self_hosted_models?
        ::Ability.allowed?(current_user, :read_dap_self_hosted_model) &&
          ::Ability.allowed?(current_user, :update_dap_self_hosted_model)
      end

      def beta_models_enabled?
        ::Ai::TestingTermsAcceptance.has_accepted?
      end

      def instance_model_selection_view_model
        {
          basePath: url_helpers.admin_gitlab_duo_model_selection_index_path,
          instanceId: ::Gitlab::CurrentSettings.uuid,
          modelOptions: model_choices_as_options,
          betaModelsEnabled: beta_models_enabled?,
          canManageInstanceModelSelection: can_manage_instance_model_selection?,
          canManageSelfHostedModels: can_manage_self_hosted_models?,
          canManageDapSelfHostedModels: can_manage_dap_self_hosted_models?,
          modelSelectionAllowlistAvailable: model_selection_allowlist_available?,
          isDedicatedInstance: dedicated_instance?,
          duoConfigurationSettingsPath: url_helpers.admin_gitlab_duo_configuration_index_url,
          purchaseCreditsPath: url_helpers.subscription_portal_self_managed_purchase_credits_url
        }
      end

      private

      def model_selection_allowlist_available?
        ::Ability.allowed?(current_user, :read_model_selection_allowlist) &&
          ::Ability.allowed?(current_user, :update_model_selection_allowlist)
      end

      def url_helpers
        ::Gitlab::Routing.url_helpers
      end
    end
  end
end

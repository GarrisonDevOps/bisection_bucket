# frozen_string_literal: true

module Resolvers
  module Ai
    module FeatureSettings
      class FeatureSettingsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type ::Types::Ai::FeatureSettings::FeatureSettingType.connection_type, null: false

        argument :self_hosted_model_id,
          ::Types::GlobalIDType[::Ai::SelfHostedModel],
          required: false,
          description: 'Global ID of the self-hosted model.'

        def resolve(self_hosted_model_id: nil)
          return unless authorized_user?

          feature_settings = ::Ai::FeatureSettings::FeatureSettingFinder.new(
            self_hosted_model_id: self_hosted_model_id
          ).execute

          dap_settings = ::Gitlab::Graphql::Representation::AiFeatureSetting
            .decorate(feature_settings[:dap],
              with_self_hosted_models: dap_self_hosted_models?,
              with_gitlab_models: gitlab_models?,
              model_definitions: gitlab_model_definitions)

          classic_settings = ::Gitlab::Graphql::Representation::AiFeatureSetting
            .decorate(feature_settings[:classic],
              with_self_hosted_models: self_hosted_models?,
              with_gitlab_models: gitlab_models?,
              model_definitions: gitlab_model_definitions)

          dap_settings + classic_settings
        end

        private

        def authorized_user?
          [:manage_instance_model_selection, :manage_self_hosted_models_settings].any? do |ability|
            Ability.allowed?(current_user, ability)
          end
        end

        def dap_self_hosted_models?
          return false unless self_hosted_models_requested?

          Ability.allowed?(current_user, :read_dap_self_hosted_model)
        end

        def self_hosted_models?
          return false unless self_hosted_models_requested?

          Ability.allowed?(current_user, :manage_self_hosted_models_settings)
        end

        def self_hosted_models_requested?
          context.query.sanitized_query_string.include?('validModels')
        end

        def gitlab_models?
          gitlab_models_requested = context.query.sanitized_query_string.include?('validGitlabModels')

          return false unless gitlab_models_requested

          Ability.allowed?(current_user, :manage_instance_model_selection)
        end

        def gitlab_model_definitions
          ::Ai::ModelSelection::ModelDefinitions.fetch(current_user).parser
        end
      end
    end
  end
end

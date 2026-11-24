# frozen_string_literal: true

module Types
  module Ai
    module FeatureSettings
      # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
      class FeatureSettingType < ::Types::BaseObject
        graphql_name 'AiFeatureSetting'
        description 'Duo Chat feature setting'

        field :feature, String, null: false, description: 'Identifier for the AI feature.'

        field :provider, String, null: false, description: 'Humanized name for the AI feature, e.g "Code Completion".'

        field :title, String, null: true, description: 'Displayed AI feature name.'

        field :main_feature, String, null: true, description: 'Displayed name of the main feature.'

        field :compatible_llms, [String], null: true, description: 'LLMs Compatible with the feature.'

        field :release_state, String, null: true, description: 'Current release state of the feature.'

        field :self_hosted_model,
          Types::Ai::SelfHostedModels::SelfHostedModelType,
          null: true,
          description: 'Self-hosted model selected for use with the AI feature.'

        field :gitlab_model,
          Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'GitLab model selected for use with the AI feature.'

        field :default_gitlab_model,
          Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'GitLab model selected for use with the AI feature.'

        field :valid_models,
          Types::Ai::SelfHostedModels::SelfHostedModelType.connection_type,
          null: false,
          description: 'Compatible self-hosted models for the feature.'

        # rubocop: disable GraphQL/ExtractType -- they are not part of the same object
        field :valid_gitlab_models,
          Types::Ai::ModelSelection::OfferedModelType.connection_type,
          null: false,
          description: 'Valid GitLab managed models for the feature.'
        # rubocop: enable GraphQL/ExtractType

        field :allow_list,
          ::Types::Ai::ModelSelection::AllowListType,
          null: true,
          experiment: { milestone: '19.1' },
          description: 'Model selection allowlist for the feature. ' \
            'Returns `null` when the current user cannot read the allowlist or when the feature does not support one.'

        def allow_list
          return unless Ability.allowed?(current_user, :read_model_selection_allowlist)

          object.allow_list
        end

        private

        def current_user
          context[:current_user]
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end

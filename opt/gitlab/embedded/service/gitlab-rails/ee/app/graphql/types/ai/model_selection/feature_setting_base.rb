# frozen_string_literal: true

module Types
  module Ai
    module ModelSelection
      # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
      class FeatureSettingBase < ::Types::BaseObject
        graphql_name 'AiModelSelectionFeatureSettingBase'

        field :feature, String, null: false, description: 'Identifier for the AI feature.'

        field :title, String, null: true, description: 'Displayed AI feature name.'

        field :main_feature, String, null: true, description: 'Displayed name of the main feature.'

        field :selected_model, ::Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'Identifier of the current model selected.'

        field :default_model, ::Types::Ai::ModelSelection::OfferedModelType,
          null: true,
          description: 'LLMs Compatible with the feature.'

        field :selectable_models, [Types::Ai::ModelSelection::OfferedModelType],
          null: false,
          description: 'LLMs Compatible with the feature.'

        field :allow_list,
          ::Types::Ai::ModelSelection::AllowListType,
          null: true,
          experiment: { milestone: '19.1' },
          description: 'Model selection allowlist for the feature. ' \
            'Returns `null` when the current user cannot read the allowlist or when the feature does not support one.'

        def selected_model
          return unless object.offered_model_ref

          {
            ref: object.offered_model_ref,
            name: object.offered_model_name
          }
        end

        def allow_list
          return unless Ability.allowed?(current_user, :read_model_selection_allowlist, allow_list_subject)

          object.allow_list
        end

        private

        def current_user
          context[:current_user]
        end

        # Subclasses (e.g. namespace setting) override this to pass the
        # group/namespace to the policy. Instance subclasses leave it nil so
        # the global `EE::GlobalPolicy` rules apply.
        def allow_list_subject
          nil
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end

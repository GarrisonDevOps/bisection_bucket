# frozen_string_literal: true

module Types
  module Ai
    module ModelSelection
      # rubocop: disable Graphql/AuthorizeTypes -- authorization handled by parent field on FeatureSettingType / FeatureSettingBase
      class AllowListType < ::Types::BaseObject
        graphql_name 'AiModelSelectionAllowList'
        description 'Model selection allowlist for an AI feature'

        # Shared by the namespace and instance/admin surfaces. The namespace
        # payload carries the group (`:group` boundary); the instance payload
        # leaves `group` nil so resolution falls through to `:instance`.
        authorize_granular_token permissions: :read_model_selection_allowlist,
          boundaries: [
            { boundary: :group, boundary_type: :group, assignable_when: [:saas] },
            { boundary: :instance, boundary_type: :instance, assignable_when: [:admin] }
          ]

        field :enabled, GraphQL::Types::Boolean, null: false,
          description: 'Whether the model selection allowlist is enabled for the feature.'

        field :models,
          ::Types::Ai::ModelSelection::AllowListModelType.connection_type,
          null: false,
          description: 'All GitLab-managed models offered for the feature with their effective allowlist state. ' \
            'Includes both allowed and disallowed models so callers can render a complete allowlist UI.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end

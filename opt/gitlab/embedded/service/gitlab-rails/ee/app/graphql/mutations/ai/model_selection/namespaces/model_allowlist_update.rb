# frozen_string_literal: true

module Mutations
  module Ai
    module ModelSelection
      module Namespaces
        class ModelAllowlistUpdate < BaseMutation
          graphql_name 'AiModelSelectionNamespaceModelAllowlistUpdate'
          description 'Updates the namespace-level model selection allowlist for an AI feature.'

          include ::Mutations::Ai::ModelSelection::AllowListPayload

          authorize :update_model_selection_allowlist

          authorize_granular_token permissions: :update_model_selection_allowlist, boundary_argument: :group_id,
            boundary_type: :group,
            assignable_when: [:saas]

          argument :group_id, ::Types::GlobalIDType[::Group],
            required: true,
            description: 'Group whose model allowlist is being configured.'

          argument :feature, ::Types::Ai::FeatureSettings::FeaturesEnum,
            required: true,
            description: 'AI feature whose model allowlist is being configured.'

          argument :allowlist_enabled, GraphQL::Types::Boolean,
            required: true,
            description: 'Whether the model selection allowlist is enabled for the feature.'

          argument :allowlist_model_refs, [GraphQL::Types::String],
            required: true,
            description: 'Identifiers of the GitLab-managed models allowed for the feature. ' \
              'Ignored when `allowlistEnabled` is false.'

          field :allow_list,
            ::Types::Ai::ModelSelection::AllowListType,
            null: true,
            description: 'Model selection allowlist for the feature after the update.'

          def resolve(group_id:, feature:, allowlist_enabled:, allowlist_model_refs:)
            group = authorized_find!(id: group_id)

            result = ::Ai::ModelSelection::Namespace::UpdateAllowlistService.new(
              group,
              feature: feature,
              enabled: allowlist_enabled,
              model_refs: allowlist_model_refs
            ).execute

            {
              allow_list: allow_list_payload(result),
              errors: result.errors
            }
          end
        end
      end
    end
  end
end

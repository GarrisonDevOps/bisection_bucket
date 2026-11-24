# frozen_string_literal: true

module Mutations
  module Ai
    module FeatureSettings
      class ModelAllowlistUpdate < BaseMutation
        graphql_name 'AiFeatureSettingModelAllowlistUpdate'
        description 'Updates the instance-level model selection allowlist for an AI feature.'

        include ::Mutations::Ai::ModelSelection::AllowListPayload

        authorize_granular_token permissions: :update_model_selection_allowlist, boundary: :instance,
          boundary_type: :instance,
          assignable_when: [:admin]

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

        def resolve(feature:, allowlist_enabled:, allowlist_model_refs:)
          raise_resource_not_available_error! unless allowed?

          result = ::Ai::ModelSelection::UpdateInstanceAllowlistService.new(
            feature: feature,
            enabled: allowlist_enabled,
            model_refs: allowlist_model_refs
          ).execute

          {
            allow_list: allow_list_payload(result),
            errors: result.errors
          }
        end

        private

        def allowed?
          Ability.allowed?(current_user, :update_model_selection_allowlist)
        end
      end
    end
  end
end

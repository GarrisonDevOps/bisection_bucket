# frozen_string_literal: true

module Resolvers
  module Ai
    module Chat
      class AvailableModelsResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource

        authorize :access_duo_agentic_chat

        type ::Types::Ai::Chat::AvailableModelsType, null: false

        argument :root_namespace_id,
          ::Types::GlobalIDType[::Group],
          required: false,
          description: 'Global ID of the top-level namespace the user is acting on.'

        argument :namespace_id,
          ::Types::GlobalIDType[::Group],
          required: false,
          description: 'Global ID of the namespace the user is acting on. '

        argument :project_id,
          ::Types::GlobalIDType[::Project],
          required: false,
          description: 'Global ID of the project the user is acting on.'

        def resolve(root_namespace_id: nil, namespace_id: nil, project_id: nil)
          namespace = resolve_root_namespace(
            root_namespace_id: root_namespace_id,
            namespace_id: namespace_id,
            project_id: project_id
          )

          feature_setting = feature_setting_result(namespace)
          # Without a feature setting record, we can't really perform any calculations,
          # so let's return an empty result if it's not present
          return empty_result unless feature_setting.present?

          user_model_selection = ::Ai::ModelSelection::UserModelSelection.for(
            current_user, feature_setting: feature_setting
          )

          {
            default_model: user_model_selection.default_model,
            selectable_models: user_model_selection.selectable_models,
            pinned_model: user_model_selection.pinned_model
          }
        end

        private

        def resolve_root_namespace(root_namespace_id: nil, namespace_id: nil, project_id: nil)
          resource = authorized_find!(id: project_id || namespace_id || root_namespace_id)
          resource.root_ancestor
        end

        def empty_result
          { default_model: nil, selectable_models: [], pinned_model: nil }
        end

        def feature_setting_result(namespace)
          result = ::Ai::FeatureSettingSelectionService
            .new(current_user, ::Ai::ModelSelection::FeaturesConfigurable.agentic_chat_feature_name, namespace)
            .execute

          return unless result.success? && result.payload.present?

          result.payload
        end
      end
    end
  end
end

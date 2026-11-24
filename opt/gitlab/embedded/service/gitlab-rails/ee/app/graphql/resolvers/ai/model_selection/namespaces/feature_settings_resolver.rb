# frozen_string_literal: true

module Resolvers
  module Ai
    module ModelSelection
      module Namespaces
        class FeatureSettingsResolver < BaseResolver
          include Gitlab::Graphql::Authorize::AuthorizeResource

          authorize :admin_group_model_selection

          type ::Types::Ai::ModelSelection::Namespaces::FeatureSettingType.connection_type, null: false

          argument :group_id, ::Types::GlobalIDType[::Group],
            required: true,
            description: 'Group for the model selection.'

          def resolve(group_id: nil)
            group = authorized_find!(id: group_id)

            model_definitions = fetch_model_definitions
            feature_settings = get_feature_settings(group)

            ::Gitlab::Graphql::Representation::ModelSelection::FeatureSetting.decorate(
              feature_settings,
              model_definitions: model_definitions,
              current_user: current_user
            )
          end

          private

          def get_feature_settings(group)
            ::Ai::ModelSelection::Namespaces::FeatureSettingFinder.new(group: group).execute
          end

          def fetch_model_definitions
            catalog = ::Ai::ModelSelection::ModelDefinitions.fetch(current_user)

            raise_resource_not_available_error!(catalog.error_message) unless catalog.success?

            catalog.payload
          end
        end
      end
    end
  end
end

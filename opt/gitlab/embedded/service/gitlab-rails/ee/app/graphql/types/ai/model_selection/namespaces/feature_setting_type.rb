# frozen_string_literal: true

module Types
  module Ai
    module ModelSelection
      module Namespaces
        # rubocop: disable Graphql/AuthorizeTypes -- authorization in resolver/mutation
        class FeatureSettingType < ::Types::Ai::ModelSelection::FeatureSettingBase
          graphql_name 'AiModelSelectionNamespaceFeatureSetting'
          description 'Model Selection feature setting for namespaces.'

          field :namespace, Types::GroupType,
            null: false,
            description: 'Namespace that the feature setting is set for.'

          private

          def allow_list_subject
            object.namespace
          end
        end
        # rubocop: enable Graphql/AuthorizeTypes
      end
    end
  end
end

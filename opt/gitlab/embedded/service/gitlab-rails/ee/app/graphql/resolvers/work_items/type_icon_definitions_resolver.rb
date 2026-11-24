# frozen_string_literal: true

module Resolvers
  module WorkItems
    class TypeIconDefinitionsResolver < BaseResolver
      type [::Types::WorkItems::IconDefinitionType], null: false

      def resolve
        return [] unless License.feature_available?(:configurable_work_item_types)

        ::WorkItems::TypesFramework::IconDefinitions::ICON_DEFINITIONS
      end
    end
  end
end

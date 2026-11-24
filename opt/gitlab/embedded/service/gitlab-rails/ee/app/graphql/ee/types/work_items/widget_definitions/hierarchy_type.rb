# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module WidgetDefinitions
        module HierarchyType
          extend ActiveSupport::Concern

          def allowed_child_types(parent:)
            resolve_types_through_provider(super)
          end

          def allowed_parent_types(parent:)
            resolve_types_through_provider(super)
          end

          private

          def resolve_types_through_provider(types)
            return types if types.blank?

            provider.by_ids_ordered_by_name(types.map(&:id))
          end

          def provider
            @provider ||= ::WorkItems::TypesFramework::Provider.new(context[:resource_parent])
          end
        end
      end
    end
  end
end

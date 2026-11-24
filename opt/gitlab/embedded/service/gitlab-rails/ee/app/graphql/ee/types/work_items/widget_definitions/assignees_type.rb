# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module WidgetDefinitions
        module AssigneesType
          extend ActiveSupport::Concern

          prepended do
            field :allows_multiple_assignees, GraphQL::Types::Boolean,
              null: false,
              description: 'Indicates whether multiple assignees are allowed.'
          end

          def allows_multiple_assignees
            object.widget_class.allows_multiple_assignees?(resource_parent)
          end
        end
      end
    end
  end
end

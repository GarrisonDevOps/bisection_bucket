# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class ColorInputType < BaseInputObject
        graphql_name 'WorkItemWidgetColorInput'

        argument :color,
          ::Types::ColorType,
          required: true,
          description: 'Color of the work item.'
      end
    end
  end
end

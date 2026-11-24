# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class IterationInputType < BaseInputObject
        graphql_name 'WorkItemWidgetIterationInput'

        argument :iteration_id, # rubocop:disable Graphql/ForbiddenLoadsArgument -- pre-existing code; removing `loads:` would be a breaking change
          ::Types::GlobalIDType[::Iteration],
          required: false,
          loads: ::Types::IterationType,
          description: 'Iteration to assign to the work item.'
      end
    end
  end
end

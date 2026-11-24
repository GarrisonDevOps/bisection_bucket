# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class SeverityInputType < BaseInputObject
        graphql_name 'WorkItemWidgetSeverityInput'

        argument :severity,
          ::Types::IssuableSeverityEnum,
          required: true,
          description: 'Severity of the work item.'
      end
    end
  end
end

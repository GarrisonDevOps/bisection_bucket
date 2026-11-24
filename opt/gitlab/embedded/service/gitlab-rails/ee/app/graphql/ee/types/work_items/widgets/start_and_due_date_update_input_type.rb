# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module Widgets
        module StartAndDueDateUpdateInputType
          extend ActiveSupport::Concern

          prepended do
            argument :is_fixed,
              ::GraphQL::Types::Boolean,
              required: false,
              description: 'Indicates if the work item is using fixed dates.'
          end
        end
      end
    end
  end
end

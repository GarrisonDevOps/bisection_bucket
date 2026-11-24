# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module Widgets
        module StartAndDueDateType
          extend ActiveSupport::Concern

          prepended do
            field :is_fixed,
              ::GraphQL::Types::Boolean,
              method: :fixed?,
              null: false,
              scopes: [:api, :read_api, :ai_workflows],
              description: 'Indicates if the work item is using fixed dates.'

            field :start_date_sourcing_work_item,
              ::Types::WorkItemType,
              null: true,
              description: 'Indicates which work_item sources the rolled up start date.'

            field :start_date_sourcing_milestone,
              ::Types::MilestoneType,
              null: true,
              description: 'Indicates which milestone sources the rolled up start date.'

            field :due_date_sourcing_work_item,
              ::Types::WorkItemType,
              null: true,
              description: 'Indicates which work_item sources the rolled up due date.'

            field :due_date_sourcing_milestone,
              ::Types::MilestoneType,
              null: true,
              description: 'Indicates which milestone sources the rolled up due date.'
          end
        end
      end
    end
  end
end

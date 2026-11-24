# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # rubocop:disable Graphql/AuthorizeTypes -- Disabling widget level authorization
      # as it might be too granular and we already authorize the parent work item
      class RolledupDatesType < BaseObject
        graphql_name 'WorkItemWidgetRolledupDates'
        description 'Represents the rolledup dates widget'

        implements ::Types::WorkItems::WidgetInterface

        field :start_date,
          ::Types::DateType,
          null: true,
          description: 'Start date for the work item.'

        field :start_date_fixed,
          ::Types::DateType,
          null: true,
          description: 'Fixed start date for the work item.'

        field :start_date_is_fixed,
          ::GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates if the start date for the work item is fixed.'

        field :start_date_sourcing_work_item,
          ::Types::WorkItemType,
          null: true,
          description: 'Indicates which work_item sources the rolledup start date.'

        field :start_date_sourcing_milestone,
          ::Types::MilestoneType,
          null: true,
          description: 'Indicates which milestone sources the rolledup start date.'

        field :due_date,
          ::Types::DateType,
          null: true,
          description: 'Due date for the work item.'

        field :due_date_fixed,
          ::Types::DateType,
          null: true,
          description: 'Fixed due date for the work item.'

        field :due_date_is_fixed,
          ::GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates if the due date for the work item is fixed.'

        field :due_date_sourcing_work_item,
          ::Types::WorkItemType,
          null: true,
          description: 'Indicates which work_item sources the rolledup due date.'

        field :due_date_sourcing_milestone,
          ::Types::MilestoneType,
          null: true,
          description: 'Indicates which milestone sources the rolledup due date.'
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end

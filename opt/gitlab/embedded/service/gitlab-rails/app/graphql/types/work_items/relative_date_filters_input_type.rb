# frozen_string_literal: true

module Types
  module WorkItems
    class RelativeDateFiltersInputType < BaseInputObject
      graphql_name 'WorkItemRelativeDateFiltersInput'
      description 'Date filters relative to today. Each date resolves to the start of that day ' \
        'in the instance time zone.'

      argument :created_after, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items created on or after the date.'
      argument :created_before, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items created before the date.'

      argument :updated_after, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items updated on or after the date.'
      argument :updated_before, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items updated before the date.'

      argument :closed_after, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items closed on or after the date.'
      argument :closed_before, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items closed before the date.'

      argument :due_after, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items due on or after the date.'
      argument :due_before, ::Types::WorkItems::RelativeDateInputType,
        required: false,
        description: 'Work items due before the date.'
    end
  end
end

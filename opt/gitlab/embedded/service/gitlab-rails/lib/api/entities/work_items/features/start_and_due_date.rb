# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class StartAndDueDate < Grape::Entity
          expose :start_date,
            documentation: {
              type: 'Date', example: '2022-08-17',
              desc: 'Start date of the work item. When `roll_up` is `true` and the dates are not fixed, this is the ' \
                'earliest start date of its child items and their milestones. Null if no start date is set.'
            },
            expose_nil: true

          expose :due_date,
            documentation: {
              type: 'Date', example: '2022-08-30',
              desc: 'Due date of the work item. When `roll_up` is `true` and the dates are not fixed, this is the ' \
                'latest due date of its child items and their milestones. Null if no due date is set.'
            },
            expose_nil: true

          # CE WorkItems::Widgets::StartAndDueDate#can_rollup? is always false; the EE override returns true when
          # the work item type allows child items.
          expose :roll_up,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether the start and due dates can be inherited from child items and their milestones. ' \
                'True if the work item type can have child items and date roll-up is available.'
            } do |feature, _|
            feature.can_rollup?
          end
        end
      end
    end
  end
end

::API::Entities::WorkItems::Features::StartAndDueDate.prepend_mod

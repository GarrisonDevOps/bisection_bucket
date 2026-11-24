# frozen_string_literal: true

module EE
  module API
    module Entities
      module WorkItems
        module Features
          module StartAndDueDate
            extend ActiveSupport::Concern

            prepended do
              # See WorkItems::RollupableDates#fixed? for when dates count as fixed.
              expose :is_fixed,
                documentation: {
                  type: 'Boolean', example: true,
                  desc: 'Whether the dates are set on the work item itself instead of rolled up from its child ' \
                    'work items and their milestones. Always `true` for work item types that cannot have children.'
                } do |feature, _|
                feature.fixed?
              end

              expose :start_date_sourcing_work_item,
                using: ::API::Entities::WorkItems::Features::WorkItemReference,
                documentation: {
                  type: 'Entities::WorkItems::Features::WorkItemReference',
                  desc: 'Child work item whose start date is used as the rolled-up start date. ' \
                    'Null if the dates are fixed, the start date does not come from a child work item, ' \
                    'or the current user cannot view the work item.'
                },
                expose_nil: true do |widget, options|
                readable_sourcing_record(widget.start_date_sourcing_work_item, :read_work_item, options)
              end

              expose :start_date_sourcing_milestone,
                using: ::API::Entities::Milestone,
                documentation: {
                  type: 'Entities::Milestone',
                  desc: 'Milestone of a child work item whose start date is used as the rolled-up start date. ' \
                    'Null if the dates are fixed, the start date does not come from a milestone, ' \
                    'or the current user cannot view the milestone.'
                },
                expose_nil: true do |widget, options|
                readable_sourcing_record(widget.start_date_sourcing_milestone, :read_milestone, options)
              end

              expose :due_date_sourcing_work_item,
                using: ::API::Entities::WorkItems::Features::WorkItemReference,
                documentation: {
                  type: 'Entities::WorkItems::Features::WorkItemReference',
                  desc: 'Child work item whose due date is used as the rolled-up due date. ' \
                    'Null if the dates are fixed, the due date does not come from a child work item, ' \
                    'or the current user cannot view the work item.'
                },
                expose_nil: true do |widget, options|
                readable_sourcing_record(widget.due_date_sourcing_work_item, :read_work_item, options)
              end

              expose :due_date_sourcing_milestone,
                using: ::API::Entities::Milestone,
                documentation: {
                  type: 'Entities::Milestone',
                  desc: 'Milestone of a child work item whose due date is used as the rolled-up due date. ' \
                    'Null if the dates are fixed, the due date does not come from a milestone, ' \
                    'or the current user cannot view the milestone.'
                },
                expose_nil: true do |widget, options|
                readable_sourcing_record(widget.due_date_sourcing_milestone, :read_milestone, options)
              end
            end

            private

            def readable_sourcing_record(record, ability, options)
              record if record && Ability.allowed?(options[:current_user], ability, record)
            end
          end
        end
      end
    end
  end
end

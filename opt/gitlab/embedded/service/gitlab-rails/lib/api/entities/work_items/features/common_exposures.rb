# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        module CommonExposures
          extend ActiveSupport::Concern
          include ConditionalExposureHelpers

          included do
            expose_feature :description,
              using: ::API::Entities::WorkItems::Features::Description,
              documentation: {
                type: 'Entities::WorkItems::Features::Description',
                desc: 'Description of the work item, its edit history, and task list progress.'
              },
              expose_nil: true

            expose_feature :assignees,
              using: ::API::Entities::UserBasic,
              documentation: {
                type: 'Entities::UserBasic', is_array: true,
                desc: 'Users assigned to the work item. Empty if no one is assigned.'
              },
              &:assignees

            expose_feature :labels,
              using: ::API::Entities::WorkItems::Features::Labels,
              documentation: {
                type: 'Entities::WorkItems::Features::Labels',
                desc: 'Labels applied to the work item, and whether scoped labels are available.'
              },
              expose_nil: true

            expose_feature :milestone,
              using: ::API::Entities::Milestone,
              documentation: {
                type: 'Entities::Milestone',
                desc: 'Milestone the work item belongs to. Null if no milestone is set.'
              },
              expose_nil: true,
              &:milestone

            expose_feature :start_and_due_date,
              using: ::API::Entities::WorkItems::Features::StartAndDueDate,
              documentation: {
                type: 'Entities::WorkItems::Features::StartAndDueDate',
                desc: 'Start and due dates of the work item, and whether they roll up from child items.'
              },
              expose_nil: true

            expose_feature :designs,
              using: ::API::Entities::WorkItems::Features::Designs,
              documentation: {
                type: 'Entities::WorkItems::Features::Designs',
                desc: 'State of the design collection attached to the work item.'
              },
              expose_nil: true

            expose_feature :time_tracking,
              using: ::API::Entities::WorkItems::Features::TimeTracking,
              documentation: {
                type: 'Entities::WorkItems::Features::TimeTracking',
                desc: 'Time estimate, total time spent, and time logs of the work item.'
              },
              expose_nil: true

            expose_feature :error_tracking,
              using: ::API::Entities::WorkItems::Features::ErrorTracking,
              documentation: {
                type: 'Entities::WorkItems::Features::ErrorTracking',
                desc: 'Sentry error linked to the work item.'
              },
              expose_nil: true

            expose_feature :hierarchy,
              using: ::API::Entities::WorkItems::Features::Hierarchy,
              documentation: {
                type: 'Entities::WorkItems::Features::Hierarchy',
                desc: 'Parent of the work item and whether it has a parent.'
              },
              expose_nil: true

            expose_feature :award_emoji,
              using: ::API::Entities::WorkItems::Features::AwardEmoji,
              documentation: {
                type: 'Entities::WorkItems::Features::AwardEmoji',
                desc: 'Number of upvotes and downvotes on the work item.'
              },
              expose_nil: true

            expose_feature :development,
              using: ::API::Entities::WorkItems::Features::Development,
              documentation: {
                type: 'Entities::WorkItems::Features::Development',
                desc: 'Number of merge requests that close the work item, and whether merging one closes it.'
              },
              expose_nil: true

            expose_feature :notifications,
              using: ::API::Entities::WorkItems::Features::Notifications,
              documentation: {
                type: 'Entities::WorkItems::Features::Notifications',
                desc: 'Whether the current user receives notifications for the work item.'
              },
              expose_nil: true
          end
        end
      end
    end
  end
end

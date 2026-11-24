# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      class Permissions < Grape::Entity
        # Same abilities as GraphQL's WorkItemPermissions (Types::PermissionTypes::WorkItem).
        PERMISSION_DESCRIPTIONS = {
          read_work_item: 'Whether the current user can view the work item.',
          update_work_item: 'Whether the current user can edit the work item, for example its title and description.',
          delete_work_item: 'Whether the current user can delete the work item.',
          admin_work_item: 'Whether the current user can manage the work item, for example set its weight, ' \
            'iteration, health status, or severity.',
          admin_parent_link: 'Whether the current user can add or remove the parent and child items of the work item.',
          set_work_item_metadata: 'Whether the current user can set metadata on the work item, for example ' \
            'assignees, start and due dates, and status.',
          create_note: 'Whether the current user can comment on the work item.',
          admin_work_item_link: 'Whether the current user can add or remove links between the work item and ' \
            'related items.',
          mark_note_as_internal: 'Whether the current user can make comments on the work item internal.',
          report_spam: 'Whether the current user can report the work item as spam to Akismet. True only for ' \
            'administrators, when Akismet is enabled and the work item has user agent details that were not ' \
            'submitted yet.',
          move_work_item: 'Whether the current user can move the work item to another project, or to another ' \
            'group for group work items. False for work item types other than issue, incident, ticket, ' \
            'test case, and epic.',
          clone_work_item: 'Whether the current user can copy the work item to another project, or to another ' \
            'group for group work items. False for work item types other than issue, incident, ticket, ' \
            'test case, and epic.',
          summarize_comments: 'Whether the current user can generate an AI summary of the comments on the work item.'
        }.freeze

        PERMISSION_ABILITIES = PERMISSION_DESCRIPTIONS.keys.freeze

        PERMISSION_ABILITIES.each do |ability|
          expose ability,
            documentation: {
              type: 'Boolean', example: true, desc: PERMISSION_DESCRIPTIONS[ability]
            } do |work_item, options|
              Ability.allowed?(options[:current_user], ability, work_item)
            end
        end
      end
    end
  end
end

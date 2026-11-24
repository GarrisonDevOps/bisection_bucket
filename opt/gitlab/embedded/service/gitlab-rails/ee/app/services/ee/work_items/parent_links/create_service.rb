# frozen_string_literal: true

module EE
  module WorkItems
    module ParentLinks
      module CreateService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super
        rescue ::WorkItems::SyncAsEpic::SyncAsEpicError => error
          ::Gitlab::ErrorTracking.track_exception(error, work_item_parent_id: issuable.id)

          error(_("Couldn't create link due to an internal error."), 422)
        end

        private

        override :set_parent
        def set_parent(issuable, work_item)
          if issuable.group_epic_work_item? && !synced_work_item
            ApplicationRecord.transaction do
              parent_link = super
              parent_link.work_item_syncing = true # set this attribute to skip the validation validate_legacy_hierarchy
              create_synced_epic_link!(parent_link, work_item) if parent_link.save

              parent_link
            end
          else
            super
          end
        end

        override :relate_issuables
        def relate_issuables(work_item)
          return super if synced_work_item
          return super unless sync_epic_link?

          ApplicationRecord.transaction do
            parent_link = super

            sync_relative_position(parent_link) if parent_link

            parent_link
          end
        end

        override :create_notes_and_resource_event
        def create_notes_and_resource_event(work_item, _link, _prev_parent)
          return if synced_work_item
          return if work_item.importing?

          super
        end

        override :can_admin_link?
        def can_admin_link?(work_item)
          return true if synced_work_item
          return true if work_item.importing?

          super
        end

        override :can_add_to_parent?
        def can_add_to_parent?(parent_work_item, child_work_item = nil)
          return true if child_work_item&.importing?
          return true if synced_work_item

          # For legacy epics, we allow to add child items to the epic, when the user only has read access to the group.
          # This could be the case when the group is public, or also when the group is private, but the user
          # has access to a project within the group.
          #
          # The ideal solution would be to have a Policy that takes into account the work item's namespace
          # (group or project) for both the child and the parent, and the user's access to each namespace.
          # However, this is a larger piece of work and we're deciding how to change policies for work items in
          # https://gitlab.com/gitlab-org/gitlab/-/issues/505855, which might make this change obsolete.
          #
          # To keep the same business logic that we had for legacy epics, we for now add this specific check and
          # and only check for `read` access for the parents, when they are group level work items.
          #
          # Once decision has been made, we can refactor the existing `admin_parent_link` policy.
          return can?(current_user, :read_work_item, parent_work_item) if parent_work_item.group_epic_work_item?

          super
        end

        def create_synced_epic_link!(parent_link, work_item)
          result = if work_item.group_epic_work_item?
                     handle_epic_link(parent_link, work_item)
                   else
                     handle_epic_issue(parent_link, work_item)
                   end

          return result if result[:status] == :success

          ::Gitlab::EpicWorkItemSync::Logger.error(
            message: 'Not able to create work item parent link',
            error_message: result[:message],
            group_id: issuable.namespace.id,
            work_item_parent_id: issuable.id,
            work_item_id: work_item.id
          )
          raise ::WorkItems::SyncAsEpic::SyncAsEpicError, result[:message]
        end

        def sync_relative_position(parent_link)
          if parent_link.work_item.group_epic_work_item? && parent_link.work_item.synced_epic
            legacy_epic = parent_link.work_item.synced_epic
            legacy_epic.relative_position = parent_link.relative_position
            legacy_epic.save(touch: false)
          elsif parent_link.work_item.work_item_type.issue?
            epic_issue = EpicIssue.find_by_issue_id(parent_link.work_item.id)
            epic_issue.update(relative_position: parent_link.relative_position) if epic_issue
          end
        end

        def handle_epic_link(parent_link, work_item)
          success_result = { status: :success }
          legacy_child_epic = work_item.synced_epic
          return success_result unless legacy_child_epic

          if sync_epic_link?
            legacy_child_epic.parent = issuable.synced_epic
            legacy_child_epic.move_to_start
            legacy_child_epic.work_item_parent_link = parent_link

            if legacy_child_epic.save(touch: false)
              { status: :success }
            else
              { status: :error, message: legacy_child_epic.errors.map(&:message).to_sentence }
            end
          elsif legacy_child_epic.parent.present?
            legacy_child_epic.update!(parent: nil, work_item_parent_link: nil)
            { status: :success }
          else
            success_result
          end
        end

        def handle_epic_issue(parent_link, work_item)
          success_result = { status: :success }
          child_issue = ::Issue.find_by_id(work_item.id)
          return success_result unless child_issue
          return success_result unless sync_epic_link?

          epic_issue = EpicIssue.find_or_initialize_from_parent_link(parent_link)
          epic_issue.move_to_start

          if epic_issue.save(touch: false)
            { status: :success }
          else
            { status: :error, message: epic_issue.errors.map(&:message).to_sentence }
          end
        end

        def sync_epic_link?
          issuable.synced_epic.present?
        end
      end
    end
  end
end

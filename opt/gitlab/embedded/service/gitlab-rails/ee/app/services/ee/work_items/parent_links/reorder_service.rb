# frozen_string_literal: true

module EE
  module WorkItems
    module ParentLinks
      module ReorderService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        def execute
          super
        rescue ::WorkItems::SyncAsEpic::SyncAsEpicError => _error
          error(_("Couldn't re-order due to an internal error."), 422)
        end

        private

        override :move_link
        def move_link(link, adjacent_work_item, relative_position)
          parent_changed = link.changes.include?(:work_item_parent_id)
          create_missing_synced_link!(adjacent_work_item)
          return unless adjacent_work_item&.parent_link || parent_changed
          return super unless sync_to_epic?(link)

          ApplicationRecord.transaction do
            # set this attribute to skip the validation ParentLink#validate_legacy_hierarchy
            link.work_item_syncing = true if parent_changed
            move_synced_object!(link, adjacent_work_item, relative_position) if super
          end
        end

        def create_missing_synced_link!(adjacent_work_item)
          return unless adjacent_work_item

          adjacent_parent_link = adjacent_work_item.parent_link
          # if issuable is an epic, we can create the missing parent link between epic work item and adjacent_work_item
          return unless adjacent_parent_link.blank? && adjacent_work_item.synced_epic

          adjacent_parent_link = set_parent(issuable, adjacent_work_item)
          adjacent_parent_link.relative_position = adjacent_work_item.synced_epic.relative_position
          adjacent_parent_link.save!

          # we update the adjacent_work_item's parent link but use the adjacent_work_item object.
          adjacent_work_item.reset
        end

        def move_synced_object!(link, adjacent_work_item, relative_position)
          synced_moving_object = synced_object_for(link.work_item) || build_missing_epic_issue(link)
          return unless synced_moving_object

          sync_parent_change!(link, synced_moving_object)
          reorder_synced_object(synced_moving_object, adjacent_work_item, relative_position)

          synced_moving_object.save!(touch: false)
        rescue StandardError => error
          ::Gitlab::EpicWorkItemSync::Logger.error(
            message: "Not able to sync re-ordering work item",
            error_message: error.message,
            namespace_id: issuable.namespace_id,
            synced_moving_object_id: synced_moving_object.id,
            synced_moving_object_class: synced_moving_object.class
          )

          ::Gitlab::ErrorTracking.track_exception(error, namespace_id: issuable.namespace_id)

          raise ::WorkItems::SyncAsEpic::SyncAsEpicError
        end

        # A child that had no epic before this re-order has no legacy epic_issues row to move. Build it here, or the
        # parent link is left without its legacy row: https://gitlab.com/gitlab-org/gitlab/-/issues/612058
        # Epic children are synced through `epics.parent_id`, so they never have an epic_issues row.
        def build_missing_epic_issue(link)
          return if link.work_item.work_item_type.epic?

          epic_issue = ::EpicIssue.find_or_initialize_from_parent_link(link)
          # Without a position the row sorts to the bottom of the legacy tree, even when the parent link moved to
          # the top. `ParentLinks::CreateService#handle_epic_issue` starts new rows the same way.
          epic_issue&.move_to_start

          epic_issue
        end

        def synced_object_for(work_item)
          case work_item.synced_epic
          when nil
            ::EpicIssue.find_by_issue_id(work_item.id)
          when ::Epic
            work_item.synced_epic
          end
        end

        def sync_to_epic?(link)
          return false if synced_work_item
          return false if link.work_item_parent.synced_epic.nil?

          true
        end

        def reorder_synced_object(synced_moving_object, adjacent_work_item, relative_position)
          return unless adjacent_work_item

          synced_adjacent_object = synced_object_for(adjacent_work_item)
          return unless synced_adjacent_object

          synced_moving_object.move_before(synced_adjacent_object) if relative_position == 'BEFORE'
          synced_moving_object.move_after(synced_adjacent_object) if relative_position == 'AFTER'
        end

        def sync_parent_change!(link, synced_moving_object)
          parent_attributes =
            case synced_moving_object
            when ::EpicIssue
              # set work_item_syncing to skip the validation EpicIssue#check_existing_parent_link
              { epic: link.work_item_parent.synced_epic, work_item_syncing: true }
            when ::Epic
              { parent: link.work_item_parent.synced_epic, work_item_parent_link: link }
            end

          return if link.work_item_parent == synced_moving_object.try(parent_attributes.keys[0])

          synced_moving_object.assign_attributes(parent_attributes)
          synced_moving_object.save!
        end

        override :can_admin_link?
        def can_admin_link?(work_item)
          return true if synced_work_item

          super
        end

        override :can_add_to_parent?
        def can_add_to_parent?(parent_work_item, _child_work_item = nil)
          return true if synced_work_item

          super
        end

        override :linkable?
        def linkable?(work_item)
          return true if synced_work_item
          return false if work_item.work_item_type.epic? && !work_item.namespace.licensed_feature_available?(:subepics)

          super
        end
      end
    end
  end
end

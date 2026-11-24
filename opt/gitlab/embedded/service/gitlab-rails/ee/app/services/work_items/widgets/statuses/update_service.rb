# frozen_string_literal: true

module WorkItems
  module Widgets
    module Statuses
      class UpdateService
        include Gitlab::InternalEventsTracking

        def initialize(work_item, current_user, status = :default)
          @original = work_item
          @work_item = ensure_work_item(work_item)
          @current_user = current_user

          if status == :default
            @auto_transition = true
            @status = lifecycle&.default_status_for_work_item(@work_item)
          else
            @auto_transition = false
            @status = status
          end
        end

        def execute
          return unless status_in_lifecycle?

          # Check if current status explicit values are set. Using work_item.current_status.status would follow the
          # mappings resulting in potentially current_status.custom_status_id or current_status.system_defined_status_id
          # to continue to point to a value that needs to look up a mapping.
          current_status = work_item.current_status
          return if current_status&.custom_status == status
          return if current_status&.system_defined_status == status

          update_work_item_status
          sync_original_association
          create_system_note

          return if @auto_transition

          track_internal_event(
            'change_work_item_status_value',
            namespace: work_item.project&.namespace || work_item.namespace,
            project: work_item.project,
            user: current_user,
            additional_properties: {
              label: status.category.to_s
            }
          )
        end

        private

        attr_reader :work_item, :current_user, :status

        def status_in_lifecycle?
          status && lifecycle && lifecycle.has_status_id?(status.id)
        end

        def lifecycle
          @lifecycle ||= work_item.work_item_type.status_lifecycle_for(root_ancestor&.id)
        end

        def update_work_item_status
          ensure_lifecycle_connection!

          current_status = work_item.current_status || work_item.build_current_status
          current_status.status = status

          current_status.save!
        end

        # Persist the real type<->lifecycle connection the first time status is
        # written to a type that is only masked (e.g. epic in a custom-lifecycle
        # namespace). Runs in the same write path, before the CurrentStatus
        # validations that read custom_status_enabled_for?.
        #
        # When a connection is newly created we reset the current_status
        # association: an unsaved current_status may have been built earlier in
        # the request (e.g. by status_with_fallback during webhook change
        # detection) while the type was still masked, memoizing
        # custom_status_enabled? as false. Resetting forces a fresh build so the
        # validations see the now-persisted custom lifecycle connection.
        def ensure_lifecycle_connection!
          created = ::WorkItems::Statuses::Lifecycles::Provider
            .new(root_ancestor.id)
            .ensure_connection!(work_item.work_item_type)

          work_item.association(:current_status).reset if created && !work_item.current_status&.persisted?
        end

        # `ensure_work_item` loads a fresh WorkItem instance when handed an Issue,
        # so the status is written to a different object than the caller holds.
        # Hand the caller the record we wrote (rather than resetting the
        # association, which would re-read from the database) so its
        # `previous_changes` survive for `after_update_commit` event publishing.
        # No-op when the caller passed the same object we wrote to (WorkItem
        # callers).
        def sync_original_association
          return if @original.equal?(work_item)
          return unless @original.respond_to?(:current_status)

          @original.association(:current_status).target = work_item.current_status
        end

        def create_system_note
          return unless root_ancestor.licensed_feature_available?(:work_item_status)

          return unless work_item.current_status.previous_changes.key?(:custom_status_id) ||
            work_item.current_status.previous_changes.key?(:system_defined_status_id)

          ::SystemNotes::IssuablesService.new(
            noteable: work_item,
            container: work_item.namespace,
            author: current_user
          ).change_work_item_status(work_item.current_status.status)
        end

        def root_ancestor
          work_item.resource_parent&.root_ancestor
        end

        def ensure_work_item(work_item)
          return work_item if work_item.is_a?(WorkItem)

          WorkItem.find_by_id(work_item) if work_item.is_a?(Issue)
        end
      end
    end
  end
end

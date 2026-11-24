# frozen_string_literal: true

module WorkItems
  module Lifecycles
    class UpdateService < BaseService
      InvalidLifecycleTypeError = ServiceResponse.error(
        message: 'Invalid lifecycle type. Custom lifecycle already exists.'
      )

      LifecycleUpdateForbiddenError = ServiceResponse.error(
        message: "You don't have permission to update this lifecycle."
      )

      def initialize(container:, current_user: nil, params: {})
        super
      end

      def execute
        return InvalidLifecycleTypeError if invalid_lifecycle_type?
        return LifecycleUpdateForbiddenError if lifecycle_update_forbidden?

        converting = !custom_lifecycle_present?
        result = converting ? create_custom_lifecycle! : update_custom_lifecycle!

        schedule_converted_status_backfill if converting
        track_internal_events_for_statuses
        # Track update lifecycle event for all actions on a lifecycle for now
        # including status name change and statuses reordering.
        track_update_lifecycle_event

        ServiceResponse.success(payload: { lifecycle: result })
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def update_custom_lifecycle!
        ApplicationRecord.transaction do
          apply_status_changes(params[:statuses])

          record_previous_default_statuses

          if @processed_statuses.present?
            validate_status_removal_constraints
            update_lifecycle_status_positions!
            lifecycle.assign_attributes(default_statuses_for_lifecycle(@processed_statuses, params))
          end

          lifecycle.assign_attributes(params.slice(:name))
          lifecycle.validate!

          lifecycle.updated_by = current_user if lifecycle.changed?
          lifecycle.save! if lifecycle.changed?

          handle_deferred_status_removal
          remove_system_defined_board_lists

          lifecycle
        end
      end

      def create_custom_lifecycle!
        ApplicationRecord.transaction do
          apply_status_changes(params[:statuses])

          record_previous_default_statuses
          validate_status_removal_constraints

          statuses = @processed_statuses
          default_statuses = default_statuses_for_lifecycle(
            statuses,
            params,
            fallback_lifecycle: lifecycle,
            force_resolve: true
          )

          ::WorkItems::Statuses::Custom::Lifecycle.create!(
            namespace: group,
            name: params[:name] || lifecycle.name,
            work_item_types: lifecycle.work_item_types(group),
            statuses: statuses,
            default_open_status: default_statuses[:default_open_status],
            default_closed_status: default_statuses[:default_closed_status],
            default_duplicate_status: default_statuses[:default_duplicate_status],
            created_by: current_user
          ).tap do
            # Handle mappings also when lifecycle was created from system-defined lifecycle
            # with removed statuses and mappings
            handle_deferred_status_removal
            remove_system_defined_board_lists
          end
        end
      end

      def track_update_lifecycle_event
        track_internal_event('update_custom_lifecycle',
          namespace: group,
          user: current_user
        )
      end

      def lifecycle_update_forbidden?
        custom_lifecycle? && lifecycle.namespace_id != group.id
      end

      def invalid_lifecycle_type?
        system_defined_lifecycle? && group.custom_lifecycles.exists?(name: lifecycle.name) # rubocop:disable CodeReuse/ActiveRecord -- skip
      end

      def custom_lifecycle_present?
        custom_lifecycle? && group.custom_lifecycles.exists?(id: lifecycle.id) # rubocop:disable CodeReuse/ActiveRecord -- skip
      end
    end
  end
end

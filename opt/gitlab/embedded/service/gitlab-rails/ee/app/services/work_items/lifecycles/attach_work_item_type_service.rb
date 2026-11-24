# frozen_string_literal: true

module WorkItems
  module Lifecycles
    class AttachWorkItemTypeService < BaseService
      InvalidLifecycleTypeError = ServiceResponse.error(
        message: 'Work item types can only be attached to custom lifecycles.'
      )

      AttachmentForbiddenError = ServiceResponse.error(
        message: "You don't have permission to attach work item types to this lifecycle."
      )

      WorkItemTypeUnsupportedWidgetError = ServiceResponse.error(
        message: "Work item type doesn't support the status widget."
      )

      WorkItemTypeAlreadyAttachedError = ServiceResponse.error(
        message: 'Work item type is already attached to this lifecycle.'
      )

      WorkItemTypeNotFoundError = ServiceResponse.error(
        message: 'Work item type not found.'
      )

      def execute
        return WorkItemTypeNotFoundError unless work_item_type
        return InvalidLifecycleTypeError if system_defined_lifecycle?
        return InvalidLifecycleTypeError if system_defined_target_lifecycle?
        return AttachmentForbiddenError unless target_lifecycle_in_namespace?
        return WorkItemTypeUnsupportedWidgetError unless work_item_type_supports_status?
        return WorkItemTypeAlreadyAttachedError if work_item_type_already_attached?

        result = attach_work_item_type_to_lifecycle!

        track_attach_work_item_type_event

        ServiceResponse.success(payload: { lifecycle: result })
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def attach_work_item_type_to_lifecycle!
        ApplicationRecord.transaction do
          validate_status_mappings_and_usage

          process_status_mappings if status_mappings.present?

          if lifecycle && lifecycle != target_lifecycle
            pin_masked_types_to_source_lifecycle!
            lifecycle.work_item_type_ids -= [work_item_type.id]
            lifecycle.updated_by = current_user
            lifecycle.save!
          end

          target_lifecycle.work_item_type_ids |= [work_item_type.id]
          target_lifecycle.updated_by = current_user
          target_lifecycle.save!

          target_lifecycle
        end
      end

      # A masked type (the epic) borrows the Issue lifecycle, or the first custom one when Issue has none.
      # Moving any type off the source can change what it borrows, so this runs for every move.
      # Writing the masked rows to the source first keeps them put. The moved type is skipped.
      def pin_masked_types_to_source_lifecycle!
        lifecycle_provider.masked_types_for(lifecycle).each do |masked_type|
          next if masked_type.persistable_id == work_item_type.persistable_id

          lifecycle_provider.ensure_connection!(masked_type)
        end
      end

      def validate_status_mappings_and_usage
        # Find statuses in current lifecycle that won't be available in target lifecycle
        current_statuses = lifecycle.statuses.to_a
        unavailable_statuses = current_statuses - target_lifecycle_statuses

        return unless unavailable_statuses.any?

        validate_status_usage(unavailable_statuses)
      end

      def process_status_mappings
        return unless status_mappings.present?

        # Bound existing unbounded mappings that conflict with statuses now available
        # in the target lifecycle, so the original status can be used directly.
        expire_unbounded_mappings_to_target_lifecycle_statuses

        old_statuses_by_id = lifecycle.statuses.index_by(&:id)

        status_mappings.each do |mapping_input|
          ensure_gid_is_custom_status(mapping_input[:old_status_id])
          ensure_gid_is_custom_status(mapping_input[:new_status_id])

          old_status = old_statuses_by_id[mapping_input[:old_status_id].model_id.to_i]
          unless old_status
            raise StandardError, "Status #{mapping_input[:old_status_id]} is not part of the lifecycle " \
              "or doesn't exist."
          end

          new_status = resolve_target_status(mapping_input[:new_status_id], target_lifecycle_statuses.map(&:id))

          ensure_mapped_statuses_have_same_state(old_status, new_status)

          status_role = lifecycle.role_for_status(old_status)
          # If the status is still available in the target lifecycle, we need to limit
          # the mapping to be created to the current timestamp so the status remains usable.
          # That's also the case if the old status was a default status before.
          valid_until = target_lifecycle_statuses.include?(old_status) || status_role.present? ? Time.current : nil

          create_or_update_mapping(old_status, new_status, work_item_type,
            valid_until: valid_until,
            old_status_role: status_role
          )
        end
      end

      def expire_unbounded_mappings_to_target_lifecycle_statuses
        Statuses::Custom::Mapping.where( # rubocop:disable CodeReuse/ActiveRecord -- query only used here
          namespace: group,
          work_item_type_id: work_item_type.id,
          new_status: target_lifecycle_statuses,
          valid_until: nil
        ).update_all(valid_until: Time.current)
      end

      def ensure_gid_is_custom_status(gid)
        return if gid.model_class == ::WorkItems::Statuses::Custom::Status

        raise StandardError, "Custom statuses need to be provided for mappings"
      end

      def work_item_type
        return unless params[:work_item_type_id].present?

        ::WorkItems::TypesFramework::Provider.new(container).find_by_gid(GlobalID.parse(params[:work_item_type_id]))
      end
      strong_memoize_attr :work_item_type

      def target_lifecycle
        return unless params[:lifecycle_id].present?

        find_by_gid(GlobalID.parse(params[:lifecycle_id]))
      end
      strong_memoize_attr :target_lifecycle

      def target_lifecycle_statuses
        target_lifecycle.statuses.to_a
      end
      strong_memoize_attr :target_lifecycle_statuses

      def target_lifecycle_in_namespace?
        target_lifecycle.namespace_id == group.id
      end

      def work_item_type_supports_status?
        work_item_type.widget_classes(group).include?(::WorkItems::Widgets::Status)
      end

      def work_item_type_already_attached?
        target_lifecycle.work_item_type_ids.include?(work_item_type.id)
      end

      def track_attach_work_item_type_event
        track_internal_event('attach_work_item_type_to_custom_lifecycle',
          namespace: group,
          user: current_user,
          additional_properties: {
            label: work_item_type.name
          }
        )
      end

      def lifecycle
        work_item_type.status_lifecycle_for(group.id)
      end
      strong_memoize_attr :lifecycle

      def system_defined_target_lifecycle?
        target_lifecycle.is_a?(::WorkItems::Statuses::SystemDefined::Lifecycle)
      end
    end
  end
end

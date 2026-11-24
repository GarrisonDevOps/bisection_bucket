# frozen_string_literal: true

module WorkItems
  module Lifecycles
    class DeleteService < BaseService
      InvalidLifecycleTypeError = ServiceResponse.error(
        message: 'Invalid lifecycle type. Only custom lifecycles can be deleted.'
      )

      LifecycleDeleteForbiddenError = ServiceResponse.error(
        message: "You don't have permission to delete this lifecycle."
      )

      LifecycleInUseError = ServiceResponse.error(
        message: "Cannot delete lifecycle because it is currently in use."
      )

      def initialize(container:, current_user: nil, params: {})
        super
      end

      def execute
        return InvalidLifecycleTypeError if system_defined_lifecycle?
        return LifecycleDeleteForbiddenError if lifecycle_delete_forbidden?
        return LifecycleInUseError if lifecycle_in_use?

        result = delete_custom_lifecycle!

        track_delete_lifecycle_event

        ServiceResponse.success(payload: { lifecycle: result })
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def lifecycle_delete_forbidden?
        lifecycle.namespace_id != group.id
      end

      def lifecycle_in_use?
        lifecycle&.in_use?(group.id)
      end

      def delete_custom_lifecycle!
        ApplicationRecord.transaction do
          delete_statuses!

          lifecycle.destroy!
        end
      end

      def delete_statuses!
        statuses = lifecycle.statuses

        statuses_to_delete = statuses.select do |status|
          status.can_be_deleted_from_namespace?(lifecycle)
        end

        status_ids = statuses_to_delete.map(&:id)
        WorkItems::Statuses::Custom::Status.delete_by(namespace_id: group.id, id: status_ids)
      end

      def track_delete_lifecycle_event
        track_internal_event('delete_custom_lifecycle',
          namespace: group,
          user: current_user
        )
      end
    end
  end
end

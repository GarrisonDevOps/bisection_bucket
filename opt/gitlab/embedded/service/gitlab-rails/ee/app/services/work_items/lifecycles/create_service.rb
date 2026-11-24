# frozen_string_literal: true

module WorkItems
  module Lifecycles
    class CreateService < BaseService
      def initialize(container:, current_user: nil, params: {})
        super
      end

      def execute
        result = create_custom_lifecycle!

        schedule_converted_status_backfill if converted_system_defined_lifecycle?
        track_internal_events_for_statuses
        # Even if we transition the system-defined lifecycle to custom lifecycle first
        # we only count one created lifecycle because that is the action the user performed.
        track_create_lifecycle_event

        ServiceResponse.success(payload: { lifecycle: result })
      rescue StandardError => e
        ServiceResponse.error(message: e.message)
      end

      private

      def create_custom_lifecycle!
        ApplicationRecord.transaction do
          ensure_custom_lifecycle_and_status!

          apply_status_changes(params[:statuses])

          statuses = @processed_statuses
          default_statuses = default_statuses_for_lifecycle(statuses, params)

          ::WorkItems::Statuses::Custom::Lifecycle.create!(
            namespace: group,
            name: params[:name],
            statuses: statuses,
            default_open_status: default_statuses[:default_open_status],
            default_closed_status: default_statuses[:default_closed_status],
            default_duplicate_status: default_statuses[:default_duplicate_status],
            created_by: current_user
          )
        end
      end

      def track_create_lifecycle_event
        track_internal_event('create_custom_lifecycle',
          namespace: group,
          user: current_user
        )
      end
    end
  end
end

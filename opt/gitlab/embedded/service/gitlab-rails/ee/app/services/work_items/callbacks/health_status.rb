# frozen_string_literal: true

module WorkItems
  module Callbacks
    class HealthStatus < Base
      def after_initialize
        params[:health_status] = nil if excluded_in_new_type?
        return unless params.key?(:health_status) && can_set_health_status?

        work_item.health_status = params[:health_status]
      end

      private

      def can_set_health_status?
        work_item.resource_parent&.feature_available?(:issuable_health_status) && has_permission?(:admin_work_item)
      end
    end
  end
end

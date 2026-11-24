# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    module Validations
      def validate
        if namespace.is_a?(Group) && !namespace.licensed_feature_available?(:cycle_analytics_for_groups)
          error(:missing_license)
        end
      end

      def error(error_reason)
        ServiceResponse.error(
          message: "#{self.class.name} error for namespace: #{namespace.id} (#{error_reason})",
          payload: { reason: error_reason }
        )
      end

      def success(success_reason, payload = {})
        ServiceResponse.success(payload: { reason: success_reason }.merge(payload))
      end
    end
  end
end

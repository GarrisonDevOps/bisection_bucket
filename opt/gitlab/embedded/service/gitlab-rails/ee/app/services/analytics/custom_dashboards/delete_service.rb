# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class DeleteService
      include Gitlab::Allowable

      def initialize(current_user:, dashboard:)
        @current_user = current_user
        @dashboard = dashboard
      end

      def execute
        return error_response('Dashboard not found') unless @dashboard
        return error_response('You are not authorized to delete this dashboard') unless can_delete?

        if @dashboard.destroy
          success_response
        else
          error_response(@dashboard.errors.full_messages)
        end
      end

      private

      def can_delete?
        can?(@current_user, :delete_custom_dashboard, @dashboard)
      end

      def success_response
        ServiceResponse.success(payload: { dashboard: @dashboard })
      end

      def error_response(message)
        ServiceResponse.error(message: message, payload: { dashboard: @dashboard })
      end
    end
  end
end

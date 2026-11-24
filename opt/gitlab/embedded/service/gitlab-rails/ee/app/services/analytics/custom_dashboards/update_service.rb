# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class UpdateService
      include Gitlab::Allowable

      MAX_VERSIONS_PER_DASHBOARD = 20
      VERSION_PRUNE_BATCH_SIZE = 100

      def initialize(current_user:, dashboard:, params:)
        @current_user = current_user
        @dashboard = dashboard
        @params = params
      end

      def execute
        return error_response('Dashboard not found') unless @dashboard
        return error_response('You are not authorized to update this dashboard') unless can_update?

        if @dashboard.update(dashboard_params.merge(updated_by: @current_user))
          prune_versions if @dashboard.saved_change_to_config?
          success_response
        else
          error_response(@dashboard.errors.full_messages)
        end
      end

      private

      # The name and description columns back search, so keep them in sync
      # with the title and description the dashboard renders from its config.
      def dashboard_params
        config = @params[:config]
        return @params unless config.is_a?(Hash)

        config = config.with_indifferent_access
        @params.merge(name: config[:title], description: config[:description].to_s)
      end

      def can_update?
        can?(@current_user, :update_custom_dashboard, @dashboard)
      end

      # Oldest first and bounded, so a dashboard far over the cap converges over
      # successive updates instead of deleting everything at once. The update and
      # its version are already committed, so a failed prune must not fail the request.
      def prune_versions
        return unless ::Feature.enabled?(:custom_dashboard_write_limits, @current_user)

        newest = @dashboard.dashboard_versions.maximum(:version_number)
        return if newest.nil? || newest <= MAX_VERSIONS_PER_DASHBOARD

        @dashboard.dashboard_versions
          .oldest_up_to_version(newest - MAX_VERSIONS_PER_DASHBOARD)
          .limit(VERSION_PRUNE_BATCH_SIZE)
          .delete_all
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, dashboard_id: @dashboard.id)
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

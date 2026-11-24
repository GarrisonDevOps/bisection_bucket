# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class CreateService
      include ::Gitlab::Allowable

      MAX_DASHBOARDS_PER_NAMESPACE = 50

      def initialize(current_user:, organization:, params:)
        @current_user = current_user
        @organization = organization
        @params = params
      end

      def execute
        return authorization_error unless authorized?
        return limit_error if dashboard_limit_reached?

        dashboard = ::Analytics::CustomDashboards::Dashboard.new(
          **dashboard_params,
          organization: organization,
          created_by_id: current_user.id,
          updated_by_id: current_user.id
        )

        if dashboard.save
          ServiceResponse.success(payload: { dashboard: dashboard })
        else
          ServiceResponse.error(
            message: dashboard.errors.full_messages.to_sentence,
            payload: { errors: dashboard.errors.full_messages }
          )
        end
      end

      private

      attr_reader :current_user, :organization, :params

      # The name and description columns back search, so keep them in sync
      # with the title and description the dashboard renders from its config.
      def dashboard_params
        config = params[:config]
        return params unless config.is_a?(Hash)

        config = config.with_indifferent_access
        params.merge(name: config[:title], description: config[:description].to_s)
      end

      def authorized?
        can?(current_user, :create_custom_dashboard, organization)
      end

      def authorization_error
        ServiceResponse.error(
          message: _('You are not authorized to create dashboards in this organization')
        )
      end

      # Organization-scoped dashboards (no namespace) count as their own scope.
      def dashboard_limit_reached?
        return false unless ::Feature.enabled?(:custom_dashboard_write_limits, current_user)

        ::Analytics::CustomDashboards::Dashboard
          .namespace_scoped(organization.id, params[:namespace_id])
          .limit(MAX_DASHBOARDS_PER_NAMESPACE)
          .count >= MAX_DASHBOARDS_PER_NAMESPACE
      end

      def limit_error
        ServiceResponse.error(
          message: format(
            _('The limit of %{limit} custom dashboards for this organization or namespace has been reached'),
            limit: MAX_DASHBOARDS_PER_NAMESPACE
          )
        )
      end
    end
  end
end

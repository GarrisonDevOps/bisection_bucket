# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class DashboardsLoaderService
      MAX_DB_DASHBOARDS = 100

      def initialize(current_user, organization:, params: {})
        @current_user = current_user
        @organization = organization
        @params = params
      end

      def execute
        return [] unless authorized?

        system = filtered_system_dashboards

        case @params[:scope]
        when :gitlab
          system
        when :user
          finder.execute.limit(MAX_DB_DASHBOARDS).to_a
        else
          merge_results(finder.execute.limit(MAX_DB_DASHBOARDS).to_a, system)
        end
      end

      private

      def finder
        DashboardsFinder.new(@current_user, organization: @organization, params: @params)
      end

      def merge_results(db_dashboards, system_dashboards)
        sorted_db = db_dashboards.sort_by(&:created_at).reverse
        system_dashboards + sorted_db
      end

      def filtered_system_dashboards
        dashboards = SystemDashboardsLoader.all.select { |dashboard| can_read?(dashboard) }
        return dashboards unless @params[:search].present?

        query = @params[:search].downcase
        dashboards.select { |d| d.name.to_s.downcase.include?(query) }
      end

      def authorized?
        Ability.allowed?(@current_user, :read_system_dashboard, @organization)
      end

      def can_read?(dashboard)
        Ability.allowed?(@current_user, :read_system_dashboard, dashboard)
      end
    end
  end
end

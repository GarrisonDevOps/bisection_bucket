# frozen_string_literal: true

module Geo
  module SystemCheck
    class DatabaseReplicationWorkingCheck < ::SystemCheck::BaseCheck
      set_name 'Database replication working?'
      set_skip_reason skip_reason

      def skip?
        !Gitlab::Geo.secondary? || database_replication_disabled?
      end

      def check?
        geo_health_check.replication_enabled? && geo_health_check.replication_working?
      end

      def show_error
        try_fixing_it(
          'Follow Geo setup instructions to configure primary and secondary nodes for replication'
        )

        help_page = Rails.application.routes.url_helpers.help_page_url('administration/geo/setup/database.md')
        for_more_information(help_page)
      end

      def skip_reason
        if !Gitlab::Geo.secondary?
          'not a secondary node'
        elsif database_replication_disabled?
          'database replication is disabled'
        end
      end

      private

      def database_replication_disabled?
        Gitlab::Geo.postgresql_replication_agnostic_enabled? && !geo_health_check.replication_enabled?
      end

      def geo_health_check
        @geo_health_check ||= Gitlab::Geo::HealthCheck.new
      end
    end
  end
end

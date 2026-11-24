# frozen_string_literal: true

module Geo
  module SystemCheck
    class DatabaseMigrationCheck < ::SystemCheck::BaseCheck
      set_name 'Databases schema up to date?'

      def skip?
        !Gitlab::Geo.secondary? || !geo_health_check.logical_replication_mode?
      end

      def check?
        geo_health_check.pending_migration_databases.empty?
      end

      def show_error
        pending = geo_health_check.pending_migration_databases
        try_fixing_it(
          "Databases with pending migrations: #{pending.join(', ')}",
          'Run `gitlab-rake db:migrate` on the secondary to apply pending migrations'
        )

        help_page = Rails.application.routes.url_helpers.help_page_url('administration/geo/setup/database.md')
        for_more_information(help_page)
      end

      def skip_reason
        if !Gitlab::Geo.secondary?
          'not a secondary node'
        elsif !geo_health_check.logical_replication_mode?
          'not using logical replication'
        end
      end

      private

      def geo_health_check
        @geo_health_check ||= Gitlab::Geo::HealthCheck.new
      end
    end
  end
end

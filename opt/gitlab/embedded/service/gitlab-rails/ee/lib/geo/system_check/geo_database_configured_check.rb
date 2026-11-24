# frozen_string_literal: true

module Geo
  module SystemCheck
    class GeoDatabaseConfiguredCheck < ::SystemCheck::BaseCheck
      set_name 'GitLab Geo tracking database is correctly configured'
      set_skip_reason 'not a secondary node'

      WRONG_CONFIGURATION_MESSAGE = <<~MSG
        Rails does not appear to have the configuration necessary to connect to the Geo tracking database.
        If the tracking database is running on a node other than this one, then you may need to add configuration.
      MSG
      UNHEALTHY_CONNECTION_MESSAGE = "Check the tracking database configuration as the connection " \
        "could not be established"
      NO_TABLES_MESSAGE = 'Run the tracking database migrations: gitlab-rake db:migrate:geo'
      REUSING_EXISTING_DATABASE_MESSAGE = "If you are reusing an existing tracking database, " \
        "make sure you have reset it."
      DATABASE_DOCS = 'doc/administration/geo/setup/database.md'
      TROUBLESHOOTING_DOCS = 'doc/administration/geo/replication/troubleshooting/_index.md'

      def skip?
        !Gitlab::Geo.secondary?
      end

      def multi_check
        return error_message(WRONG_CONFIGURATION_MESSAGE) unless Gitlab::Geo.geo_database_configured?
        return error_message(UNHEALTHY_CONNECTION_MESSAGE) unless database_active?
        return error_message(NO_TABLES_MESSAGE) unless tables_present?
        return error_message(REUSING_EXISTING_DATABASE_MESSAGE, TROUBLESHOOTING_DOCS) unless fresh_database?

        $stdout.puts Rainbow('yes').green
        true
      end

      private

      def tables_present?
        !geo_health_check.tracking_database_needs_migration?
      end

      def database_active?
        database_connection.active? || database_connection.select_value('SELECT 1')
      rescue StandardError => e
        $stdout.puts e.message
        false
      end

      def geo_health_check
        @geo_health_check ||= Gitlab::Geo::HealthCheck.new
      end

      def fresh_database?
        !geo_health_check.reusing_existing_tracking_database?
      end

      def database_connection
        @database_connection ||= ::Geo::TrackingBase.connection
      end

      def error_message(message, docs = DATABASE_DOCS)
        $stdout.puts Rainbow('no').red
        try_fixing_it(message)
        for_more_information(docs)

        false
      end
    end
  end
end

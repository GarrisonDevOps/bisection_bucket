# frozen_string_literal: true

module Gitlab
  module Database
    # Runs the search path check on each database for the "Search path" section
    # on /admin/database_pre_upgrade_checks.
    class SearchPathInformation # rubocop:disable Search/NamespacedClass -- PostgreSQL search_path, not GitLab search
      def self.execute(database_names: DatabaseInformation::DEFAULT_DATABASE_NAMES)
        new(database_names: database_names).execute
      end

      def initialize(database_names: DatabaseInformation::DEFAULT_DATABASE_NAMES)
        @database_names = database_names
      end

      def execute
        {
          databases: @database_names.index_with { |name| collect_for_database(name) }
        }
      end

      private

      def collect_for_database(database_name)
        model = Gitlab::Database.database_base_models[database_name]
        return { error: "Unknown database: #{database_name}" } unless model

        Diagnostics::Checks::SchemaResolution.new(model.connection).execute
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, database_name: database_name)
        { error: "Failed to gather information for database: #{database_name}" }
      end
    end
  end
end

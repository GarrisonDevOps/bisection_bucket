# frozen_string_literal: true

module SystemCheck
  module App
    class AdvancedSearchMigrationsCheck < SystemCheck::BaseCheck
      set_name 'All migrations must be finished before doing a major upgrade'
      set_skip_reason 'skipped (Advanced Search is disabled)'
      set_check_pass -> { 'yes' }
      set_check_fail -> { fail_info }

      PENDING_DOCS_URL =
        'doc/integration/advanced_search/elasticsearch.md#all-migrations-must-be-finished-before-doing-a-major-upgrade'
      UNREACHABLE_DOCS_URL = 'doc/integration/advanced_search/elasticsearch.md'

      def skip?
        !Gitlab::CurrentSettings.current_application_settings.elasticsearch_indexing?
      end

      # SystemCheck::SimpleExecutor rescues StandardError and prints only the message,
      # so the unreachable case is reported as a check failure rather than propagated.
      #
      # #check?, .fail_info and #show_error are separate executor callbacks, so each
      # probes the cluster itself rather than sharing state across the three calls.
      def check?
        !::Elastic::DataMigrationService.pending_migrations!
      rescue ::Elastic::DataMigrationService::ClusterUnreachableError
        false
      end

      def show_error
        ::Elastic::DataMigrationService.pending_migrations!

        for_more_information(PENDING_DOCS_URL)
        try_fixing_it(
          'Wait for all advanced search migrations to complete.',
          'To list pending migrations, run `sudo gitlab-rake gitlab:elastic:list_pending_migrations`'
        )
      rescue ::Elastic::DataMigrationService::ClusterUnreachableError
        for_more_information(UNREACHABLE_DOCS_URL)
        try_fixing_it(
          'Check that the search cluster is running and reachable from this node, then run this check again.',
          'To check the connection, run `sudo gitlab-rake gitlab:elastic:info`'
        )
      end

      def self.fail_info
        ::Elastic::DataMigrationService.pending_migrations!

        "no (You have #{pending_migrations_count} pending #{'migration'.pluralize(pending_migrations_count)}.)"
      rescue ::Elastic::DataMigrationService::ClusterUnreachableError => e
        "no (Unable to determine migration status: #{e.message})"
      end

      def self.pending_migrations_count
        ::Elastic::DataMigrationService.pending_migrations&.size || 0
      end
    end
  end
end

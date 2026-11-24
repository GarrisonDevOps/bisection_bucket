# frozen_string_literal: true

module Search
  module Elastic
    module MigrationObsolete
      def migrate
        # rubocop:disable Gitlab/DocumentationLinks/HardcodedUrl -- Development purpose
        log "Migration has been deleted in the last major version upgrade. " \
          "Migrations are supposed to be finished before upgrading major version " \
          "https://docs.gitlab.com/update/upgrading_from_source/#upgrading-to-a-new-major-version." \
          "To correct this issue, recreate your index from scratch: " \
          "https://docs.gitlab.com/ee/integration/elasticsearch/troubleshooting/indexing.html#last-resort-to-recreate-an-index."
        # rubocop:enable Gitlab/DocumentationLinks/HardcodedUrl

        fail_migration_halt_error!
      end

      def completed?
        false
      end

      def obsolete?
        true
      end
    end
  end
end

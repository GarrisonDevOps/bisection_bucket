# frozen_string_literal: true

module Security
  module ScanProfiles
    # Keeps the denormalized `archived` column on `security_scan_profiles_projects`
    # in sync with project and group archival.
    #
    # The archive *and* unarchive services both publish these events -- they share the
    # Projects::ArchiveEvents and Namespaces::Groups::ArchiveEvents concerns -- and
    # neither payload carries the new state, so it is read back from the database.
    class ProcessArchivedEventsWorker
      include Gitlab::EventStore::Subscriber

      idempotent!
      deduplicate :until_executing, including_scheduled: true
      data_consistency :sticky
      feature_category :security_testing_configuration
      concurrency_limit -> { 25 }
      defer_on_database_health_signal :gitlab_sec, [:security_scan_profiles_projects], 1.minute

      BATCH_SIZE = 100

      def handle_event(event)
        attached_project_ids(event).each_slice(BATCH_SIZE) do |project_ids|
          Security::ScanProfileProject.sync_archived_for(project_ids)
        end
      end

      private

      # Narrowed to projects that actually have scan profile rows, so the array
      # stays small even for a group with tens of thousands of projects.
      # `pluck_primary_key` is required: the narrowing query runs on `gitlab_sec`
      # and cannot take a `projects` relation as a subquery.
      def attached_project_ids(event)
        case event
        when ::Projects::ProjectArchivedEvent
          Security::ScanProfileProject.attached_project_ids([event.data[:project_id]])
        when ::Namespaces::Groups::GroupArchivedEvent
          Gitlab::Database::NamespaceProjectIdsEachBatch.new(
            group_id: event.data[:group_id],
            resolver: ->(batch) { Security::ScanProfileProject.attached_project_ids(batch.pluck_primary_key) },
            batch_size: BATCH_SIZE
          ).execute
        else
          []
        end
      end
    end
  end
end

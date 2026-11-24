# frozen_string_literal: true

module Security
  module ScanProfiles
    class CleanOldNamespaceConnectionsService
      include Gitlab::ExclusiveLeaseHelpers
      include Security::ScanProfiles::SchedulesTriageCoverageUpdate

      NAMESPACE_BATCH_SIZE = 200
      PROJECT_BATCH_SIZE = 100
      LEASE_TIMEOUT = 5.minutes
      RETRY_DELAY = 15.seconds
      LEASE_RETRY_WITH_TRAVERSAL = 0
      LEASE_RETRY_WITHOUT_TRAVERSAL = 10
      LEASE_WAIT_WITHOUT_TRAVERSAL = 10.seconds

      def self.execute(group_id, traverse_hierarchy = true)
        new(group_id, traverse_hierarchy).execute
      end

      def initialize(group_id, traverse_hierarchy)
        @group_id = group_id
        @traverse_hierarchy = traverse_hierarchy
      end

      def execute
        return unless group.present?

        clean_old_connections
      end

      attr_reader :group_id, :traverse_hierarchy

      private

      def group
        @group ||= Group.find_by_id(group_id)
      end

      def root_ancestor
        @root_ancestor ||= group.root_ancestor
      end

      def clean_old_connections
        if traverse_hierarchy
          clean_hierarchy_connections
        else
          clean_direct_namespace_connections
        end
      end

      def clean_hierarchy_connections
        cursor = { current_id: group_id, depth: [group_id] }
        iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)

        iterator.each_batch(of: NAMESPACE_BATCH_SIZE) do |namespace_ids|
          process_namespace_batch(namespace_ids)
        end
      end

      def clean_direct_namespace_connections
        process_namespace_batch([group_id])
      end

      def process_namespace_batch(namespace_ids)
        projects_by_namespace = load_projects_grouped_by_namespace(namespace_ids)

        projects_by_namespace.each do |namespace_id, namespace_projects|
          process_namespace_projects(namespace_id, namespace_projects)
        end
      end

      def load_projects_grouped_by_namespace(namespace_ids)
        Project.in_namespace(namespace_ids)
         .select(:id, :namespace_id)
         .order_by_primary_key
         .group_by(&:namespace_id)
      end

      def process_namespace_projects(namespace_id, namespace_projects)
        project_ids = namespace_projects.map(&:id)

        project_ids.each_slice(PROJECT_BATCH_SIZE) do |project_id_batch|
          delete_batch_with_lock(project_id_batch, namespace_id)
        end
      end

      def delete_batch_with_lock(project_ids, namespace_id)
        lease_key = Security::ScanProfiles.update_lease_key(namespace_id)

        in_lock(lease_key, ttl: LEASE_TIMEOUT, **lock_retry_options) do
          delete_scan_profile_projects(project_ids)
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => error
        handle_lock_failure(error, namespace_id)
      end

      def delete_scan_profile_projects(project_ids)
        scope = Security::ScanProfileProject.by_project_id(project_ids).not_in_root_namespace(root_ancestor)
        deleted_rows = scope.delete_all_returning(:project_id, :security_scan_profile_id)

        enqueue_triage_coverage_update(remediation_project_ids(deleted_rows))
      end

      def lock_retry_options
        return { retries: LEASE_RETRY_WITH_TRAVERSAL } if traverse_hierarchy

        { retries: LEASE_RETRY_WITHOUT_TRAVERSAL, sleep_sec: LEASE_WAIT_WITHOUT_TRAVERSAL }
      end

      def handle_lock_failure(error, namespace_id)
        raise error unless traverse_hierarchy

        Security::ScanProfiles::CleanOldNamespaceConnectionsWorker.perform_in(
          RETRY_DELAY,
          namespace_id,
          false # traverse_hierarchy = false to only process this specific namespace again
        )
      end
    end
  end
end

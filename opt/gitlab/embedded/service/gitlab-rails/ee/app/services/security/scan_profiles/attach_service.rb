# frozen_string_literal: true

module Security
  module ScanProfiles
    class AttachService
      include BaseServiceUtility
      include Gitlab::ExclusiveLeaseHelpers

      BATCH_SIZE = 500
      LEASE_TIMEOUT = 5.minutes
      RETRY_DELAY = 30.seconds

      def self.execute(...)
        new(...).execute
      end

      def initialize(
        group, scan_profile, current_user:, traverse_hierarchy: true, operation_id: nil, mode: :set
      )
        @group = group
        @scan_profile = scan_profile
        @current_user = current_user
        @traverse_hierarchy = traverse_hierarchy
        @operation_id = operation_id
        @mode = mode
        @errors = []
        @rescheduled_namespaces = Set.new
      end

      def execute
        return error('Scan profile does not belong to group hierarchy') unless valid_namespace?

        attach_profile_to_projects

        @errors.present? ? error(@errors) : success
      end

      private

      attr_reader :group, :scan_profile, :current_user, :traverse_hierarchy, :operation_id,
        :mode

      def valid_namespace?
        scan_profile.namespace_id == group.root_ancestor.id
      end

      def attach_profile_to_projects
        if traverse_hierarchy
          cursor = { current_id: group.id, depth: [group.id] }
          iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: cursor)

          iterator.each_batch(of: BATCH_SIZE) do |namespace_ids|
            namespace_ids.each do |namespace_id|
              process_namespace_with_lock(namespace_id)
            end
          end
        else
          process_namespace_with_lock(group.id)
        end
      end

      def process_namespace_with_lock(namespace_id)
        relation = Project.in_namespace(namespace_id).order_by_primary_key

        relation.each_batch(of: BATCH_SIZE) do |batch|
          insert_batch_with_lock(namespace_id, batch)
        end
      end

      def insert_batch_with_lock(namespace_id, batch)
        lease_key = "#{Security::ScanProfiles.update_lease_key(namespace_id)}:profile:#{scan_profile.id}"

        # Give up on the first attempt instead of sleeping: this runs in a Sidekiq thread that holds a
        # concurrency-limit slot for the whole sleep, and the lease is held for up to LEASE_TIMEOUT.
        in_lock(lease_key, ttl: LEASE_TIMEOUT, retries: 0) do
          result = Security::ScanProfiles::ProjectAttachService.execute(
            profile: scan_profile,
            current_user: current_user,
            projects: batch.to_a,
            mode: mode
          )

          @errors.concat(result[:errors]) if result[:errors].any?
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => error
        handle_lock_failure(error, namespace_id)
      end

      def handle_lock_failure(error, namespace_id)
        raise Security::ScanProfiles::LeaseTakenError, error.message unless traverse_hierarchy

        # The retry job reprocesses the whole namespace, so schedule it once however many of the
        # namespace's batches lose the lease. Remaining batches still try: each one that wins the
        # lease is work the retry job no longer has to redo.
        return unless @rescheduled_namespaces.add?(namespace_id)

        # Deliberately drop operation_id: the operation's total_items is fixed at creation and does not
        # count retry jobs, so a retry that reports back can finalize the operation early, and one that
        # arrives after finalization exits on operation_exists? without attaching anything.
        Security::ScanProfiles::AttachWorker.perform_in(
          RETRY_DELAY, namespace_id, scan_profile.id, current_user.id, nil, false, { 'mode' => mode.to_s }
        )
      end
    end
  end
end

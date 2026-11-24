# frozen_string_literal: true

module Security
  class ProcessTrackedContextGroupTransferEventsWorker
    include Gitlab::EventStore::Subscriber

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :sticky

    # Each event walks a whole group hierarchy, so this is coarse-grained work compared to the
    # per-project jobs it enqueues.
    concurrency_limit -> { 10 }

    feature_category :vulnerability_management

    def handle_event(event)
      args = project_ids(event).zip

      log_extra_metadata_on_done(:project_ids_count, args.size)

      return if args.empty?

      # rubocop:disable Scalability/BulkPerformWithContext -- allow context omission
      ::Security::SyncTrackedContextTraversalIdsWorker.bulk_perform_async(args)
      # rubocop:enable Scalability/BulkPerformWithContext
    end

    private

    def project_ids(event)
      group = Group.find_by_id(event.data[:group_id])

      return [] unless group

      Gitlab::Database::NamespaceProjectIdsEachBatch.new(
        group_id: group.id,
        resolver: method(:project_ids_with_tracked_contexts)
      ).execute
    end

    # Project ids are inlined as VALUES because tracked contexts live on `gitlab_sec` and projects
    # on `main`, so they cannot be joined. LATERAL with LIMIT 1 stops at the first match per id.
    def project_ids_with_tracked_contexts(batch)
      # rubocop:disable CodeReuse/ActiveRecord -- Does not work outside this context.
      id_list = Arel::Nodes::ValuesList.new(batch.pluck_primary_key.map { |v| [v] }).to_sql
      filter_query = Security::ProjectTrackedContext.where('project_ids.id = project_id').limit(1).select(1)

      Security::ProjectTrackedContext.from(
        "(#{id_list}) AS project_ids(id), " \
          "LATERAL (#{filter_query.to_sql}) AS #{Security::ProjectTrackedContext.table_name}"
      ).pluck("project_ids.id")
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end

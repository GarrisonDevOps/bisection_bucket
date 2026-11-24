# frozen_string_literal: true

module Search
  module Elastic
    # Re-indexes every document under a group that moved to a different organization so its
    # `organization_id` and `organization_traversal_ids` are rebuilt from the new organization.
    #
    # The transfer only rewrites `organization_id` via `update_all`, so no model callback fires
    # and no document is removed: the group stays top-level, which leaves `traversal_ids` and
    # routing untouched. Every affected document therefore needs an upsert, never a delete.
    #
    # Repository content is re-indexed with `force`. gitlab-elasticsearch-indexer only re-reads
    # files that changed since the last indexed commit, and a transfer changes none, so without
    # it blobs, commits and wiki blobs would keep the organization they were written with.
    class OrganizationTransferredEventWorker
      include Gitlab::EventStore::Subscriber
      include Search::Worker
      prepend ::Geo::SkipSecondary

      data_consistency :delayed
      urgency :low
      pause_control :advanced_search
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      defer_on_database_health_signal :gitlab_main,
        [:namespaces, :projects, :project_namespaces, :milestones], 10.minutes

      BATCH_SIZE = 100

      # Group-owned documents that carry organization fields.
      GROUP_ASSOCIATIONS = %i[epics milestones work_items].freeze

      # The project associations a backfill indexes, which is the set that carries
      # organization fields. Shared rather than restated so the two cannot drift; the
      # strings are because Sidekiq arguments must be JSON-native types. Repository content
      # is not here: the indexer writes it, so #reindex_repository handles it separately.
      PROJECT_ASSOCIATIONS =
        ::Elastic::ProcessInitialBookkeepingService::INDEXED_PROJECT_ASSOCIATIONS.map(&:to_s).freeze

      def handle_event(event)
        return true unless Gitlab::CurrentSettings.elasticsearch_indexing?

        group_id = event.data[:group_id]
        group = Group.find_by_id(group_id)
        return if group.nil?

        # Only rows that already carry the new organization have actually moved.
        # TopLevelGroupService moves the root group row alone and publishes straight away;
        # its descendants and their projects follow later under their own event. Without
        # this filter that first event would re-index, and force a repository re-index of,
        # an entire tree that has not changed yet, and the second event would do it again.
        organization_id = event.data[:new_organization_id]

        cursor = { current_id: group_id, depth: [group_id] }
        iterator = ::Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespace, cursor: cursor)
        iterator.each_batch(of: BATCH_SIZE) do |ids|
          track_groups(ids, organization_id)
          track_projects(ids, organization_id)
        end
      end

      private

      def track_groups(namespace_ids, organization_id)
        groups = ::Group.id_in(namespace_ids).in_organization(organization_id).select(&:use_elasticsearch?)
        return if groups.empty?

        ::Elastic::ProcessBookkeepingService.track!(*groups)
        ::Elastic::ProcessBookkeepingService.maintain_indexed_namespace_associations!(
          *groups, associations_to_index: GROUP_ASSOCIATIONS
        )

        groups.each { |group| reindex_wiki(group) }
      end

      def track_projects(namespace_ids, organization_id)
        ::Project.by_project_namespace(namespace_ids).in_organization(organization_id)
          .with_namespace.find_each do |project|
          # Project documents are indexed regardless of limited indexing, so they are always
          # tracked. ElasticAssociationIndexerWorker narrows the association list itself when
          # the project is not indexed.
          ::Elastic::ProcessBookkeepingService.track!(project)
          ElasticAssociationIndexerWorker.perform_async(project.class.name, project.id, PROJECT_ASSOCIATIONS)

          reindex_repository(project)
        end
      end

      # Repository content follows limited indexing, unlike the project document itself.
      def reindex_repository(project)
        return unless project.use_elasticsearch?

        ::Search::Elastic::CommitIndexerWorker.perform_async(project.id, { 'force' => true })
        reindex_wiki(project)
      end

      # A transfer can cover a whole group tree, so spread the wiki jobs the way
      # `Groups::TransferService` does rather than enqueue them all at once.
      def reindex_wiki(container)
        ElasticWikiIndexerWorker.perform_in(
          next_wiki_interval, container.id, container.class.name, { 'force' => true }
        )
      end

      # Counts every wiki job this run schedules, groups and projects alike. A per-batch
      # offset would restart at zero each BATCH_SIZE namespaces and pile the whole tree
      # into the first BATCH_SIZE seconds, which is the opposite of spreading.
      def next_wiki_interval
        @wiki_jobs_scheduled ||= 0
        interval = @wiki_jobs_scheduled % ElasticWikiIndexerWorker::MAX_JOBS_PER_HOUR
        @wiki_jobs_scheduled += 1

        interval
      end
    end
  end
end

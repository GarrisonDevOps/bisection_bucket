# frozen_string_literal: true

module Search
  module Elastic
    class GroupArchivedEventWorker
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

      def handle_event(event)
        return true unless Gitlab::CurrentSettings.elasticsearch_indexing?

        group_id = event.data[:group_id]
        group = Group.find_by_id(group_id)
        return if group.nil?

        cursor = { current_id: group_id, depth: [group_id] }
        iterator = Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespace, cursor: cursor)
        iterator.each_batch do |ids|
          Project.by_project_namespace(ids).with_namespace.find_each do |project|
            project.maintain_elasticsearch_update(updated_attributes: ['archived']) if project.use_elasticsearch?
          end

          track_group_milestones(ids)
        end
      end

      private

      def track_group_milestones(namespace_ids)
        indexed_group_ids = ::Group.id_in(namespace_ids).select(:id, :traversal_ids)
                                   .select(&:use_elasticsearch?).map(&:id)
        return if indexed_group_ids.empty?

        milestones = ::Milestone.of_groups(indexed_group_ids).with_group.order_by_group_and_id
        ::Gitlab::Pagination::Keyset::Iterator.new(scope: milestones).each_batch do |batch|
          ::Elastic::ProcessBookkeepingService.track!(*batch)
        end
      end
    end
  end
end

# frozen_string_literal: true

module Elastic
  class ProcessInitialBookkeepingService < Elastic::ProcessBookkeepingService
    INDEXED_PROJECT_ASSOCIATIONS = [
      :issues,
      :merge_requests,
      :snippets,
      :notes,
      :milestones,
      :work_items
    ].freeze

    class << self
      def redis_set_key(shard_number)
        "elastic:bulk:initial:#{shard_number}:zset"
      end

      def redis_score_key(shard_number)
        "elastic:bulk:initial:#{shard_number}:score"
      end

      def backfill_projects!(*projects, skip_projects: false)
        track!(*projects) unless skip_projects

        projects.each do |project|
          raise ArgumentError, 'This method only accepts Projects' unless project.is_a?(Project)

          unless project.maintaining_indexed_associations?
            maintain_indexed_associations(project, ElasticAssociationIndexerWorker::PARENT_INDEPENDENT_ASSOCIATIONS)
            next
          end

          maintain_indexed_associations(project, INDEXED_PROJECT_ASSOCIATIONS)

          ::Gitlab::Geo.skip_writes_if_replica(project) do
            ::Search::Elastic::CommitIndexerWorker.perform_async(project.id, { 'force' => true })
          end

          ElasticWikiIndexerWorker.perform_async(project.id, project.class.name, { 'force' => true })
        end
      end
    end

    def indexing_bytes_per_second_target
      Gitlab::Metrics::GlobalSearchIndexingSlis::INITIAL_INDEXED_BYTES_PER_SECOND_TARGET
    end
  end
end

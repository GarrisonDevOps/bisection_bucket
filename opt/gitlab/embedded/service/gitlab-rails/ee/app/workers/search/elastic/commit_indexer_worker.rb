# frozen_string_literal: true

module Search
  module Elastic
    class CommitIndexerWorker
      include ApplicationWorker
      include Search::Worker
      include Gitlab::ExclusiveLeaseHelpers
      prepend ::Geo::SkipSecondary

      data_consistency :delayed

      sidekiq_options retry: 2
      urgency :throttled
      idempotent!
      loggable_arguments 1, 2
      concurrency_limit -> { Gitlab::CurrentSettings.elasticsearch_max_code_indexing_concurrency }
      pause_control :advanced_search

      LOCK_RETRIES = 2
      LOCK_SLEEP_SEC = 1
      RETRY_IN_IF_LOCKED = 10.minutes

      # Performs the commits and blobs indexation
      #
      # project_id - The ID of the project to index
      # options - Options hash { 'force' => bool } forces to reindex the repository
      #
      # The indexation will cover all commits within INDEXED_SHA..HEAD
      def perform(project_id, options = {})
        return true unless Gitlab::CurrentSettings.elasticsearch_indexing?

        @project = Project.find_by_id(project_id)
        unless @project&.use_elasticsearch?
          es_id = ::Search::Elastic::Helper.build_es_id(es_type: Project.es_type, target_id: project_id)
          delete_project = @project.nil?
          ElasticDeleteProjectWorker.perform_async(project_id, es_id, 'delete_project' => delete_project)
          return true
        end

        force = !!options['force']
        search_indexing_duration_s = Benchmark.realtime do
          key = "#{self.class.name}/#{project_id}"
          ttl = Search::Elastic::Indexer.timeout + 1.minute
          @ret = in_lock(key, ttl: ttl, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP_SEC) do
            Search::Elastic::Indexer.new(@project, force: force).run
          end
        end

        if @ret
          # If the indexer was locked (return = nil),
          # or the project no longer exists in the database (return = false)
          # we do not want to log anything
          logger.info(
            project_id: project_id,
            search_indexing_duration_s: search_indexing_duration_s,
            jid: jid
          )

          Gitlab::Metrics::GlobalSearchIndexingSlis
            .record_apdex(elapsed: search_indexing_duration_s, document_type: 'Code')

          if force && @project.statistics
            log_extra_metadata_on_done(:commit_count, @project.statistics.commit_count)
            log_extra_metadata_on_done(:repository_size, @project.statistics.repository_size)
          end
        end

        @ret
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        self.class.perform_in(RETRY_IN_IF_LOCKED, project_id, options)
      end
    end
  end
end

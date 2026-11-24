# frozen_string_literal: true

module Search
  class IndexRepairService < BaseProjectService
    include ::Gitlab::Loggable

    DELAY_INTERVAL = 5.minutes

    def self.execute(project, params: {})
      new(project: project, params: params).execute
    end

    def execute
      return false if ::Gitlab::Geo.replica_project?(project)
      return false unless project.should_check_index_integrity?

      repair_index_for_project if project_missing?
      repair_index_for_blobs_or_commits if should_repair_index_for_blobs_or_commits?
      repair_index_for_wikis if should_repair_index_for_wikis?
    end

    private

    def project_missing?
      query = {
        query: {
          bool: {
            filter: [
              { term: { type: 'project' } },
              { term: { id: project.id } }
            ]
          }
        }
      }

      project_count = client.count(index: Project.index_name, routing: project.es_parent, body: query)['count']

      project_count == 0
    end

    def repair_index_for_project
      logger.warn(
        build_structured_payload(
          message: 'project document missing from index',
          namespace_id: project.namespace_id,
          root_namespace_id: project.root_namespace.id,
          project_id: project.id
        )
      )
      index_repair_counter.increment(base_metrics_labels(Project))

      ::Elastic::ProcessBookkeepingService.track!(project)
    end

    def repair_index_for_blobs_or_commits
      index_repair_counter.increment(base_metrics_labels(Repository))
      ::Search::Elastic::CommitIndexerWorker.perform_in(rand(DELAY_INTERVAL), project.id, { 'force' => true })
    end

    def repair_index_for_wikis
      index_repair_counter.increment(base_metrics_labels(::Wiki))
      ElasticWikiIndexerWorker.perform_in(rand(DELAY_INTERVAL), project.id, project.class.name, { 'force' => true })
    end

    def blobs_completely_missing?
      query = {
        query: {
          bool: {
            filter: [
              { term: { type: 'blob' } },
              { term: { project_id: project.id } }
            ]
          }
        }
      }
      blob_count = client.count(index: Repository.index_name, routing: project.es_id, body: query)['count']
      (blob_count == 0).tap do |result|
        if result
          logger.warn(
            build_structured_payload(
              message: 'blob documents missing from index for project',
              namespace_id: project.namespace_id,
              root_namespace_id: project.root_namespace.id,
              project_id: project.id,
              project_last_repository_updated_at: project.last_repository_updated_at,
              index_status_last_commit: project.index_status&.last_commit,
              index_status_indexed_at: project.index_status&.indexed_at,
              repository_size: project.statistics&.repository_size
            )
          )
        end
      end
    end

    def commits_completely_missing?
      query = {
        query: {
          bool: {
            filter: [
              { term: { type: 'commit' } },
              { term: { rid: project.id.to_s } }
            ]
          }
        }
      }

      commit_count = client.count(
        index: ::Elastic::Latest::CommitConfig.index_name,
        routing: project.es_id,
        body: query
      )['count']
      commit_count == 0
    end

    def wikis_completely_missing?
      query = {
        query: {
          bool: {
            filter: [
              { term: { type: 'wiki_blob' } },
              { term: { project_id: project.id } }
            ]
          }
        }
      }

      routing = ::Elastic::Latest::WikiClassProxy.new(::Wiki).routing_options(
        { root_ancestor_ids: [project.root_ancestor.id] }
      )[:routing]
      wiki_count = client.count(index: ::Wiki.index_name, routing: routing, body: query)['count']

      wiki_count == 0
    end

    # Order of checks is important
    def should_repair_index_for_blobs_or_commits?
      # Use root_ref to avoid when HEAD points to non-existent branch
      # https://gitlab.com/gitlab-org/gitaly/-/issues/1446
      last_commit_for_root_ref = project.commit(project.repository.root_ref)
      return false if last_commit_for_root_ref.nil?
      return true if project.index_status.blank?
      return true unless project.index_status.last_commit == last_commit_for_root_ref.sha
      return true if commits_completely_missing?
      return false unless Gitlab::CurrentSettings.elasticsearch_code_scope?

      params[:force_repair_blobs] || blobs_completely_missing?
    end

    def should_repair_index_for_wikis?
      # Use root_ref to avoid when HEAD points to non-existent branch
      # https://gitlab.com/gitlab-org/gitaly/-/issues/1446
      last_commit_ref = project.wiki.repository.commit(project.wiki.repository.root_ref)
      return false if last_commit_ref.nil?
      return true if project.index_status.blank?
      return true unless project.index_status.last_wiki_commit == last_commit_ref.sha

      wikis_completely_missing?
    end

    def client
      @client ||= ::Gitlab::Search::Client.new
    end

    def logger
      @logger ||= ::Gitlab::Elasticsearch::Logger.build
    end

    def base_metrics_labels(klass)
      { document_type: klass.es_type }
    end

    def index_repair_counter
      @index_repair_counter ||= ::Gitlab::Metrics.counter(
        :search_advanced_index_repair_total,
        'Count of search index repair operations.'
      )
    end
  end
end

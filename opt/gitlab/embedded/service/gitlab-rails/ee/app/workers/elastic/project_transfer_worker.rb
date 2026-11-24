# frozen_string_literal: true

module Elastic
  class ProjectTransferWorker
    include ApplicationWorker
    include Search::Worker
    prepend ::Geo::SkipSecondary

    data_consistency :delayed

    idempotent!
    urgency :throttled

    def perform(project_id, old_namespace_id, new_namespace_id)
      return unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

      project = Project.find_by_id(project_id)
      return unless project

      should_invalidate_elasticsearch_indexes_cache = should_invalidate_elasticsearch_indexes_cache?(
        old_namespace_id, new_namespace_id
      )

      project.invalidate_elasticsearch_indexes_cache! if should_invalidate_elasticsearch_indexes_cache

      if project.maintaining_elasticsearch? && project.maintaining_indexed_associations?
        # if the new namespace is indexed:
        #   1. queue all project associated data for indexing to update the namespace ancestry field
        #   2. delete the project record with old routing from the index
        ::Elastic::ProcessInitialBookkeepingService.backfill_projects!(project, skip_projects: true)

        delete_old_project(project, old_namespace_id, project_only: true)
      elsif should_invalidate_elasticsearch_indexes_cache && ::Gitlab::CurrentSettings.elasticsearch_indexing?
        # if the new namespace isn't indexed:
        #   1. delete the project associated data from the index asynchronously

        delete_old_project(project, old_namespace_id)
      end

      # projects are always indexed
      # queue for indexing after transfer to update the namespace ancestry field
      ::Elastic::ProcessInitialBookkeepingService.track!(project)

      # delete all project associated documents with old namespace ancestry asynchronously
      ::Search::Elastic::DeleteWorker.perform_async(
        'task' => 'all',
        'traversal_id' => project.namespace.elastic_namespace_ancestry,
        'project_id' => project.id
      )
    end

    private

    def should_invalidate_elasticsearch_indexes_cache?(old_namespace_id, new_namespace_id)
      # When a project is moved to a new namespace, invalidate the Elasticsearch cache if
      # Elasticsearch limit indexing is enabled and the indexing settings are different between the two namespaces.
      return false unless ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?

      old_namespace = Namespace.find_by_id(old_namespace_id)
      new_namespace = Namespace.find_by_id(new_namespace_id)

      return ::Gitlab::CurrentSettings.elasticsearch_limit_indexing? unless old_namespace && new_namespace

      old_namespace.use_elasticsearch? != new_namespace.use_elasticsearch?
    end

    def delete_old_project(project, old_namespace_id, options = {})
      options[:namespace_routing_id] = old_namespace_id
      ElasticDeleteProjectWorker.perform_async(project.id, project.es_id, **options)
    end
  end
end

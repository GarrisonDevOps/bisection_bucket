# frozen_string_literal: true

module Elastic
  module ProjectsSearch
    extend ActiveSupport::Concern

    include ApplicationVersionedSearch

    BLOB_AND_COMMIT_TRACKED_FIELDS = %i[archived visibility_level].freeze
    WIKI_TRACKED_FIELDS = %i[archived visibility_level].freeze

    included do
      extend ::Gitlab::Utils::Override

      def use_elasticsearch?
        ::Gitlab::CurrentSettings.elasticsearch_indexes_project?(self)
      end

      def maintaining_indexed_associations?
        use_elasticsearch?
      end

      override :maintaining_elasticsearch?
      def maintaining_elasticsearch?
        ::Gitlab::CurrentSettings.elasticsearch_indexing?
      end

      override :maintain_elasticsearch_create
      def maintain_elasticsearch_create
        # Call CommitIndexerWorker to create an IndexStatus record for an empty repo
        ::Search::Elastic::CommitIndexerWorker.perform_async(id) if empty_repo?
        ::Elastic::ProcessInitialBookkeepingService.track!(self)
      end

      override :maintain_elasticsearch_update
      def maintain_elasticsearch_update(updated_attributes: previous_changes.keys)
        # avoid race condition if project is deleted before Elasticsearch update completes
        return if pending_delete?

        updated_attributes = updated_attributes.map(&:to_sym)
        if (updated_attributes & BLOB_AND_COMMIT_TRACKED_FIELDS).any? && !::Gitlab::Geo.secondary?
          ::Search::Elastic::CommitIndexerWorker.perform_async(id, { 'force' => true })
        end

        if (updated_attributes & WIKI_TRACKED_FIELDS).any?
          ElasticWikiIndexerWorker.perform_async(id, self.class.name, { 'force' => true })
        end

        super
      end

      override :maintain_elasticsearch_destroy
      def maintain_elasticsearch_destroy
        ElasticDeleteProjectWorker.perform_async(id, es_id, delete_project: true)
      end

      def invalidate_elasticsearch_indexes_cache!
        ::Gitlab::CurrentSettings.invalidate_elasticsearch_indexes_cache_for_project!(id)
      end
    end
  end
end

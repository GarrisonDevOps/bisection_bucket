# frozen_string_literal: true

class ReindexProjectsToApplyRouting < Elastic::Migration
  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Project
  UPDATE_BATCH_SIZE = 100

  def migrate
    if completed?
      log 'Skipping migration since it is already applied', index_name: index_name

      return
    end

    log 'Start reindexing', index_name: index_name, batch_size: batch_size

    document_references = process_batch!

    log 'Reindexing batch has been processed', index_name: index_name, documents_count: document_references.size
  rescue StandardError => e
    log_raise 'migrate failed', error_class: e.class, error_mesage: e.message
  end

  def completed?
    doc_count = remaining_documents_count

    log 'Checking the number of documents left without routing', remaining_count: doc_count

    doc_count == 0
  end

  def es_parent(id)
    project = Project.find_by_id(id)

    if project
      "n_#{project.root_ancestor.id}"
    else
      log "Project not found: #{id}. Scheduling ElasticDeleteProjectWorker"
      es_id = ::Search::Elastic::Helper.build_es_id(es_type: Project.es_type, target_id: id)
      ElasticDeleteProjectWorker.perform_async(id, es_id)
    end
  end

  private

  def remaining_documents_count
    helper.refresh_index(index_name: index_name)
    count = client.count(index: index_name, body: query_without_routing)['count']
    set_migration_state(remaining_count: count)
    count
  end

  def query_without_routing
    { query: { bool: { must_not: { exists: { field: '_routing' } } } } }
  end

  def process_batch!
    results = client.search(index: index_name, body: query_without_routing.merge(size: batch_size))
    hits = results.dig('hits', 'hits') || []

    document_references = hits.map do |hit|
      id = hit.dig('_source', 'id')
      es_id = hit['_id']

      Search::Elastic::DocumentReference.new(self.class::DOCUMENT_TYPE, id, es_id, es_parent(id))
    end

    document_references.each_slice(UPDATE_BATCH_SIZE) do |refs|
      ::Elastic::ProcessInitialBookkeepingService.track!(*refs)

      delete_documents(refs.map(&:db_id))
    end

    document_references
  end

  def delete_documents(ids)
    log "Deleting #{ids.count} documents from #{index_name}"

    response = client.delete_by_query(
      index: index_name, conflicts: 'proceed', wait_for_completion: false,
      body: query_for_ids(ids)
    )

    log_raise "Failed to delete #{DOCUMENT_TYPE}", failures: response['failures'] if response['failures'].present?
  end

  def query_for_ids(ids)
    {
      query: {
        bool: {
          filter: [
            { terms: { id: ids } }
          ],
          must_not: { exists: { field: '_routing' } }
        }
      }
    }
  end

  def index_name
    self.class::DOCUMENT_TYPE.__elasticsearch__.index_name
  end
end

ReindexProjectsToApplyRouting.prepend ::Search::Elastic::MigrationObsolete

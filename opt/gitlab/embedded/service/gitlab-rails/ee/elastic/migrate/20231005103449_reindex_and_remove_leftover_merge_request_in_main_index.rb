# frozen_string_literal: true

class ReindexAndRemoveLeftoverMergeRequestInMainIndex < Elastic::Migration
  ELASTIC_TIMEOUT = '5m'

  batched!
  retry_on_failure

  def migrate
    if completed?
      log 'Migration Completed', total_remaining: 0
      return
    end

    merge_request_ids = batch_of_merge_request_ids_to_reindex
    Elastic::ProcessInitialBookkeepingService.track!(*MergeRequest.id_in(merge_request_ids))
    remove_merge_requests_from_main_index!(merge_request_ids)
  end

  def completed?
    total_remaining = remaining_documents_count
    set_migration_state(documents_remaining: total_remaining)
    log('Checking if migration is finished', total_remaining: total_remaining)
    total_remaining == 0
  end

  private

  def batch_of_merge_request_ids_to_reindex
    results = client.search(index: index_name, body: { query: query }, size: batch_size)
    results['hits']['hits'].map { |hit| hit['_source']['id'] }
  end

  def remove_merge_requests_from_main_index!(merge_request_ids)
    q = query
    q[:bool][:filter] << { terms: { 'id' => merge_request_ids } }
    client.delete_by_query(index: index_name, wait_for_completion: true, timeout: ELASTIC_TIMEOUT, refresh: true,
      conflicts: 'proceed', body: { query: q })
  end

  def remaining_documents_count
    helper.refresh_index(index_name: index_name)
    client.count(index: index_name, body: { query: query })['count']
  end

  def query
    { bool: { filter: [{ term: { type: 'merge_request' } }] } }
  end

  def index_name
    Elastic::Latest::Config.index_name
  end
end

ReindexAndRemoveLeftoverMergeRequestInMainIndex.prepend ::Search::Elastic::MigrationObsolete

# frozen_string_literal: true

class ReindexAndRemoveLeftoverNotesFromMainIndex < Elastic::Migration
  ELASTIC_TIMEOUT = '5m'

  batched!
  batch_size 2000
  throttle_delay 3.minutes
  retry_on_failure

  def migrate
    if completed?
      log 'Migration Completed', total_remaining: 0
      return
    end

    note_ids = batch_of_note_ids_to_reindex
    Elastic::ProcessInitialBookkeepingService.track!(*Note.id_in(note_ids))
    remove_notes_from_main_index!(note_ids)
  end

  def completed?
    total_remaining = remaining_documents_count
    set_migration_state(documents_remaining: total_remaining)
    log('Checking if migration is finished', total_remaining: total_remaining)
    total_remaining == 0
  end

  private

  def batch_of_note_ids_to_reindex
    results = client.search(index: index_name, body: { query: query }, size: batch_size)
    results['hits']['hits'].map { |hit| hit['_source']['id'] }
  end

  def remove_notes_from_main_index!(note_ids)
    q = query
    q[:bool][:filter] << { terms: { 'id' => note_ids } }
    client.delete_by_query(index: index_name, wait_for_completion: true, timeout: ELASTIC_TIMEOUT,
      conflicts: 'proceed', refresh: true, body: { query: q })
  end

  def remaining_documents_count
    helper.refresh_index(index_name: index_name)
    client.count(index: index_name, body: { query: query })['count']
  end

  def query
    { bool: { filter: [{ term: { type: 'note' } }] } }
  end

  def index_name
    Elastic::Latest::Config.index_name
  end
end

ReindexAndRemoveLeftoverNotesFromMainIndex.prepend ::Search::Elastic::MigrationObsolete

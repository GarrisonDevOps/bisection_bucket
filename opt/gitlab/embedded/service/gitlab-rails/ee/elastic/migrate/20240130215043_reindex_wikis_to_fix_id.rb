# frozen_string_literal: true

class ReindexWikisToFixId < Elastic::Migration
  include ::Search::Elastic::MigrationHelper

  batched!
  throttle_delay 5.minutes
  retry_on_failure

  ELASTIC_TIMEOUT = '5m'
  MAX_BATCH_SIZE = 50
  SCHEMA_VERSION = 24_02

  def migrate
    if completed?
      log 'Migration Completed', total_remaining: 0
      return
    end

    set_migration_state(batch_size: batch_size) if migration_state[:batch_size].blank?

    remaining_rids_to_reindex.each do |rid|
      m = rid.match(/wiki_(?<type>project|group)_(?<id>\d+)/)
      ElasticWikiIndexerWorker.perform_in(rand(throttle_delay).seconds, m[:id], m[:type].capitalize, force: true)
    end
  end

  def completed?
    total_remaining = remaining_documents_count
    set_migration_state(documents_remaining: total_remaining)
    log('Checking if migration is finished', total_remaining: total_remaining)
    total_remaining == 0
  end

  def batch_size
    migration_state[:batch_size].presence || [get_number_of_shards(index_name: index_name), MAX_BATCH_SIZE].min
  end

  private

  def remaining_rids_to_reindex
    results = client.search(
      index: index_name,
      body: {
        size: 0, query: query_with_old_schema_version, aggs: { rids: { terms: { size: batch_size, field: 'rid' } } }
      }
    )
    rids_hist = results.dig('aggregations', 'rids', 'buckets') || []
    rids_hist.pluck('key') # rubocop: disable CodeReuse/ActiveRecord -- no ActiveRecord relation
  end

  def remaining_documents_count
    helper.refresh_index(index_name: index_name)
    client.count(index: index_name, body: { query: query_with_old_schema_version })['count']
  end

  def query_with_old_schema_version
    { range: { schema_version: { lt: SCHEMA_VERSION } } }
  end

  def index_name
    Elastic::Latest::WikiConfig.index_name
  end
end

ReindexWikisToFixId.prepend ::Search::Elastic::MigrationObsolete

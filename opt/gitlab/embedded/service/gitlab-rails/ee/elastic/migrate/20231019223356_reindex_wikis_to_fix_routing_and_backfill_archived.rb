# frozen_string_literal: true

class ReindexWikisToFixRoutingAndBackfillArchived < Elastic::Migration
  include ::Search::Elastic::MigrationHelper

  batched!
  throttle_delay 5.minutes
  retry_on_failure

  ELASTIC_TIMEOUT = '5m'
  MAX_BATCH_SIZE = 50
  SCHEMA_VERSION = 23_10

  def migrate
    if completed?
      log 'Migration Completed', total_remaining: 0
      return
    end

    set_migration_state(batch_size: batch_size) if migration_state[:batch_size].blank?

    remaining_rids_to_reindex.each do |rid|
      match = rid.match(/wiki_(project|group)_(\d+)/)
      ElasticWikiIndexerWorker.perform_in(rand(throttle_delay).seconds, match[2], match[1].capitalize, force: true)
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
    rids_hist.pluck('key') # rubocop: disable CodeReuse/ActiveRecord
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

ReindexWikisToFixRoutingAndBackfillArchived.prepend ::Search::Elastic::MigrationObsolete

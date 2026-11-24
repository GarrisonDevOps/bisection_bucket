# frozen_string_literal: true

module ClickHouse
  # rubocop: disable CodeReuse/ActiveRecord -- Building worker-specific ActiveRecord and ClickHouse queries
  class EventAuthorsConsistencyCronWorker
    include ApplicationWorker
    include ClickHouseWorker
    include ClickHouse::Concerns::ConsistencyWorker # defines perform
    include Gitlab::ExclusiveLeaseHelpers

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management
    tags :clickhouse

    MAX_AUTHOR_DELETIONS = 2000

    private

    def collect_values(ids)
      missing_user_ids_from_batch = missing_user_ids(ids)
      context[:last_processed_id] = ids.last
      missing_user_ids_from_batch = cap_to_remaining_deletions(missing_user_ids_from_batch) if strict_caps?
      context[:author_records_to_delete].concat(missing_user_ids_from_batch)

      to_be_deleted_size = context[:author_records_to_delete].size
      metadata[:modifications] = to_be_deleted_size

      if to_be_deleted_size >= MAX_AUTHOR_DELETIONS
        metadata[:status] = :limit_reached
        return
      end

      metadata[:status] = :over_time if runtime_limiter.over_time?
    end

    def process_collected_values
      ids = context[:author_records_to_delete]
      return if strict_caps? && ids.empty?

      query = ClickHouse::Client::Query.new(
        raw_query: 'ALTER TABLE events DELETE WHERE author_id IN ({author_ids:Array(UInt64)})',
        placeholders: { author_ids: ids.to_json }
      )

      execute_mutation(query)

      query = ClickHouse::Client::Query.new(
        raw_query: 'ALTER TABLE event_authors DELETE WHERE author_id IN ({author_ids:Array(UInt64)})',
        placeholders: { author_ids: ids.to_json }
      )

      execute_mutation(query)
    end

    def cap_to_remaining_deletions(missing_ids)
      remaining = MAX_AUTHOR_DELETIONS - context[:author_records_to_delete].size
      return missing_ids if missing_ids.size <= remaining

      kept = missing_ids.sort.first(remaining)
      # The cursor stops at the highest kept id so the ids above it are retried on the next run.
      context[:last_processed_id] = kept.last
      kept
    end

    def init_context
      @context = { author_records_to_delete: [], last_processed_id: 0 }
    end

    def table
      'event_authors'
    end

    def batch_column
      'author_id'
    end

    def pluck_column
      'author_id'
    end

    def missing_user_ids(ids)
      value_list = Arel::Nodes::ValuesList.new(ids.map { |id| [id] })
      User
        .from("(#{value_list.to_sql}) AS user_ids(id)")
        .where('NOT EXISTS (SELECT 1 FROM users WHERE id = user_ids.id)')
        .pluck(:id)
    end
  end
  # rubocop: enable CodeReuse/ActiveRecord
end

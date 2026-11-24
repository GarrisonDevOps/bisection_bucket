# frozen_string_literal: true

module ClickHouse
  class EventPathsConsistencyCronWorker
    include ApplicationWorker
    include ClickHouseWorker
    include ClickHouse::Concerns::ConsistencyWorker # defines perform
    include Gitlab::ExclusiveLeaseHelpers

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management
    tags :clickhouse

    MAX_RECORD_MODIFICATIONS = 500

    private

    def collect_values(paths)
      traversal_ids_by_id = paths.each_with_object({}) do |path, hash|
        traversal_ids = path.split('/').map(&:to_i)
        hash[traversal_ids.last] = traversal_ids
      end

      namespaces_by_id = Namespace
        .select(:id, :traversal_ids)
        .id_in(traversal_ids_by_id.keys)
        .index_by(&:id)

      traversal_ids_by_id.each do |id, old_traversal_ids|
        old_path = to_path(old_traversal_ids)
        if !namespaces_by_id.key?(id)
          context[:paths_to_delete] << [id, old_path]
        elsif namespaces_by_id[id].traversal_ids != old_traversal_ids
          context[:paths_to_update] << [id, old_path, to_path(namespaces_by_id[id].traversal_ids)]
        end

        context[:last_processed_id] = id

        break if strict_caps? && collected_modifications >= MAX_RECORD_MODIFICATIONS
      end

      metadata[:modifications] = collected_modifications

      if metadata[:modifications] >= MAX_RECORD_MODIFICATIONS
        metadata[:status] = :limit_reached
        return
      end

      return unless runtime_limiter.over_time?

      metadata[:status] = :over_time
    end

    def collected_modifications
      context[:paths_to_update].size + context[:paths_to_delete].size
    end

    def to_path(traversal_ids)
      "#{traversal_ids.join('/')}/"
    end

    # The path ends with the namespace_id the cursor is saved as.
    def sort_key(path)
      path.split('/').last.to_i
    end

    def process_collected_values
      delete_records_from_click_house(context[:paths_to_delete])
      update_records_in_click_house(context[:paths_to_update])
    end

    def table
      'event_namespace_paths'
    end

    def batch_column
      'namespace_id'
    end

    def pluck_column
      'path'
    end

    def init_context
      @context = { paths_to_delete: [], paths_to_update: [], last_processed_id: 0 }
    end

    def delete_records_from_click_house(id_paths)
      return if id_paths.empty?

      paths = id_paths.map(&:second).map { |value| "'#{value}'" }.join(',')
      query = ClickHouse::Client::Query.new(
        raw_query: "ALTER TABLE events DELETE WHERE path IN (#{paths})"
      )

      execute_mutation(query)

      query = ClickHouse::Client::Query.new(
        raw_query: 'ALTER TABLE event_namespace_paths DELETE WHERE namespace_id IN ({namespace_ids:Array(UInt64)})',
        placeholders: { namespace_ids: id_paths.map(&:first).to_json }
      )

      execute_mutation(query)
    end

    def update_records_in_click_house(paths_to_update)
      paths_to_update.each do |id, old_path, new_path|
        query = ClickHouse::Client::Query.new(
          raw_query:
            'ALTER TABLE events UPDATE path={new_path:String} WHERE path = {old_path:String}',
          placeholders: { new_path: new_path, old_path: old_path }
        )
        execute_mutation(query)

        query = ClickHouse::Client::Query.new(
          raw_query:
          'ALTER TABLE event_namespace_paths UPDATE path={new_path:String} WHERE namespace_id = {namespace_id:UInt64}',
          placeholders: { new_path: new_path, namespace_id: id }
        )
        execute_mutation(query)
      end
    end
  end
end

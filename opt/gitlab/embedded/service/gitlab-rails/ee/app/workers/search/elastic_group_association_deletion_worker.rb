# frozen_string_literal: true

module Search
  class ElasticGroupAssociationDeletionWorker
    include ApplicationWorker
    include Search::Worker
    prepend ::Geo::SkipSecondary

    MAX_JOBS_PER_HOUR = 3600

    sidekiq_options retry: 3
    data_consistency :delayed
    urgency :throttled
    idempotent!
    pause_control :advanced_search

    def perform(group_id, ancestor_id, options = {})
      return unless Gitlab::CurrentSettings.elasticsearch_indexing?

      group = Group.find_by_id(group_id)
      options = options.with_indifferent_access
      return process_removal(group_id, ancestor_id) unless options[:include_descendants]

      # We have the return condition here because we still want to remove the deleted items in the above call
      return if group.nil?

      # rubocop: disable CodeReuse/ActiveRecord -- We need only the ids of self_and_descendants groups
      group.self_and_descendants.each_batch do |groups|
        process_removal(groups.pluck(:id), ancestor_id)
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end

    private

    def client
      @client ||= ::Gitlab::Search::Client.new
    end

    def process_removal(group_ids, ancestor_id)
      remove_work_items(group_ids, ancestor_id)
      remove_milestones(group_ids, ancestor_id)
    end

    def remove_work_items(group_ids, ancestor_id)
      delete_by_query(
        index: ::Search::Elastic::Types::WorkItem.index_name,
        routing: "group_#{ancestor_id}",
        filters: [{ terms: { namespace_id: Array.wrap(group_ids) } }, { prefix: { traversal_ids: "#{ancestor_id}-" } }],
        group_ids: group_ids,
        ancestor_id: ancestor_id
      )
    end

    def remove_milestones(group_ids, ancestor_id)
      delete_by_query(
        index: ::Elastic::Latest::Config.index_name,
        routing: "n_#{ancestor_id}",
        filters: [
          { term: { type: ::Milestone.es_type } },
          { terms: { namespace_id: Array.wrap(group_ids) } },
          { prefix: { traversal_ids: "#{ancestor_id}-" } }
        ],
        group_ids: group_ids,
        ancestor_id: ancestor_id
      )
    end

    def delete_by_query(index:, routing:, filters:, group_ids:, ancestor_id:)
      client.delete_by_query(
        {
          index: index,
          routing: routing,
          conflicts: 'proceed',
          timeout: '10m',
          body: { query: { bool: { filter: filters } } }
        }
      )
    rescue Elasticsearch::Transport::Transport::Errors::NotFound => e
      # Index may not exist yet (e.g., in test environments or fresh instances)
      logger.debug(
        message: 'Elasticsearch index not found during group association deletion',
        Labkit::Fields::ERROR_MESSAGE => e.message,
        group_ids: group_ids,
        ancestor_id: ancestor_id
      )
    end
  end
end

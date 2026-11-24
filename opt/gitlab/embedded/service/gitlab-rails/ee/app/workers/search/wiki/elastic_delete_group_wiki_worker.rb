# frozen_string_literal: true

# Support bulk delete
module Search
  module Wiki
    class ElasticDeleteGroupWikiWorker
      MAX_JOBS_PER_HOUR = 3600

      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      data_consistency :delayed
      urgency :throttled
      idempotent!
      pause_control :advanced_search

      def perform(group_id, options = {})
        return unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        options = options.with_indifferent_access
        helper = Search::Elastic::Helper.default
        helper.remove_wikis_from_the_standalone_index(group_id, 'Group', options[:namespace_routing_id])
      end
    end
  end
end

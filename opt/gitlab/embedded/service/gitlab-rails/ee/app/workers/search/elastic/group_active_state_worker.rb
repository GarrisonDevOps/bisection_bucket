# frozen_string_literal: true

module Search
  module Elastic
    # The indexed `active` field is ancestor-aware, so archiving a group or scheduling it
    # for deletion makes every descendant's document stale, not just its own.
    class GroupActiveStateWorker
      include ApplicationWorker
      include Search::Worker
      prepend ::Geo::SkipSecondary

      MAX_JOBS_PER_HOUR = 3600

      data_consistency :delayed
      urgency :throttled
      idempotent!
      pause_control :advanced_search

      def perform(group_id)
        return unless Gitlab::CurrentSettings.elasticsearch_indexing?

        group = Group.find_by_id(group_id)
        return if group.nil?

        # Checked per batch, not once on the changed group: under limited indexing a
        # subgroup can be indexed while its parent is not, and the parent's change is
        # what makes the subgroup's document stale.
        group.self_and_descendants.each_batch do |batch|
          indexed = batch.select(&:use_elasticsearch?)
          next if indexed.empty?

          ::Elastic::ProcessBookkeepingService.track!(*indexed)
        end
      end
    end
  end
end

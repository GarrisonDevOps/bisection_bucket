# frozen_string_literal: true

module Search
  module Zoekt
    # Redis cache for the language tally the indexer counted, and whether it truncated the count.
    # Keyed without pagination or language-filter params so counts stay stable as the user ticks
    # checkboxes. Populated only via a dedicated aggregation-mode Zoekt call (see
    # SearchResults#fetch_language_tally), which is the only request that asks the indexer to count.
    class AggregationCache
      include Gitlab::Utils::StrongMemoize

      # Longer TTL than Search::Zoekt::Cache because the tally is stable across
      # pagination and language ticks, amortising the cost of a full Zoekt call.
      EXPIRES_IN = 30.minutes
      # For a tally the indexer never reported. An entry suppresses the aggregation call for its
      # whole lifetime -- a read that hits it does not re-fetch -- so this bounds how long counts
      # stay missing once an indexer that can aggregate is up.
      UNREPORTED_EXPIRES_IN = 1.minute

      # Normalise nil/absent (REST) and explicit false (GraphQL) to share one cache entry.
      BOOLEAN_FILTERS = %i[exclude_forks include_archived].freeze

      TALLY_KEY = 'tally'
      TRUNCATED_KEY = 'truncated'

      def initialize(query, current_user:, filters:, group_id:, project_id:, search_mode: :exact)
        @query = query
        @current_user = current_user
        @filters = normalize_filters(filters || {})
        @group_id = group_id
        @project_id = project_id
        @search_mode = search_mode.to_sym
      end

      def read
        entry&.fetch(TALLY_KEY, nil)
      end

      # True when the indexer stopped counting before the result stream ended, so the tally is a
      # subset of the corpus rather than all of it.
      def truncated?
        entry&.fetch(TRUNCATED_KEY, false) == true
      end

      # An empty tally is cached too, or every render re-issues the aggregation-mode Zoekt call,
      # which can never hit the cache. Its lifetime turns on why it is empty, which the caller knows
      # and the stored tally does not -- hence counts_reported rather than tally.empty?.
      #
      # Unconditional rather than nx, so a stale entry from an older stored shape self-heals on
      # the first miss instead of pinning reads to a miss for a full TTL. This trades away nx's
      # concurrency guard: racing writers can leave a truncated tally in place of a complete one.
      def write(tally, truncated: false, counts_reported: true)
        with_redis do |redis|
          redis.set(
            cache_key,
            Marshal.dump({ TALLY_KEY => tally, TRUNCATED_KEY => truncated }),
            ex: counts_reported ? EXPIRES_IN : UNREPORTED_EXPIRES_IN
          )
        end

        clear_memoization(:entry)
      end

      private

      attr_reader :query, :current_user, :filters, :group_id, :project_id, :search_mode

      def cache_key
        user_id = current_user&.id || 0
        # Braces pin the key to a single Redis Cluster slot (same convention as Search::Zoekt::Cache).
        "cache:zoekt:{#{user_id}}/language_aggregation/#{fingerprint}"
      end

      def entry
        raw = with_redis { |redis| redis.get(cache_key) }
        return unless raw

        Marshal.load(raw) # rubocop:disable Security/MarshalLoad -- we wrote this ourselves in #write
      end
      strong_memoize_attr :entry

      def fingerprint
        scope_key = "g#{group_id}-p#{project_id}"
        data = "#{query}-#{scope_key}-#{search_mode}-#{Gitlab::Json.generate(filters.sort)}"
        OpenSSL::Digest.hexdigest('SHA256', data)
      end

      def with_redis(&block)
        Gitlab::Redis::Cache.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- not ActiveRecord
      end

      def normalize_filters(input)
        # num_context_lines cannot change a tally -- the indexer forces it to 0 when aggregating --
        # so keying on it would fragment the cache into one entry per context setting.
        without_language = input.with_indifferent_access.except(:language, :num_context_lines)

        BOOLEAN_FILTERS.each_with_object(without_language) do |key, hash|
          hash[key] = Gitlab::Utils.to_boolean(hash[key], default: false)
        end
      end
    end
  end
end

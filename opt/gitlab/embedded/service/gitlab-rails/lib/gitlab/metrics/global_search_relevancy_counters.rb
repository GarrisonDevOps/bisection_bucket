# frozen_string_literal: true

module Gitlab
  module Metrics
    # Relevancy signal for Global Search: whether a search returned anything
    # and whether a result was clicked, separate from the apdex/error-rate
    # SLIs in global_search_slis.rb, which grade latency.
    #
    # Counts page views (web, API, GraphQL), not distinct searches.
    module GlobalSearchRelevancyCounters
      # Split at the top-five boundary so GSM-505's top-five click-through
      # share can be queried as position_bucket=~"1|2-3|4-5", without also
      # counting clicks on positions 6-10 (gitlab-org/gitlab#639902).
      POSITION_BUCKETS = {
        (1..1) => '1',
        (2..3) => '2-3',
        (4..5) => '4-5',
        (6..10) => '6-10'
      }.freeze
      DEFAULT_POSITION_BUCKET = '11+'
      SOURCES = %w[web api graphql].freeze

      class << self
        include Gitlab::Utils::StrongMemoize

        # Entry point for the `extra_trackers:` hook in config/events/click_search_result.yml.
        # Gitlab::InternalEvents calls this for every click_search_result event, server-side,
        # regardless of which controller/API endpoint received the click POST.
        def track_event(event_name, label: nil, value: nil, search_type: nil, **)
          return unless event_name == 'click_search_result'

          record_result_click(search_type: search_type, scope: label, position: value)
        end

        # source distinguishes web (user-facing) from api/graphql (often scripted) traffic --
        # requested so a zero-result rate meant to measure relevancy for users isn't skewed by
        # polling or existence-check callers that expect zero results on purpose.
        def record_search(search_type:, scope:, zero_results:, source:)
          requests_counter.increment(
            search_type: clamp_search_type(search_type),
            scope: clamp_scope(scope),
            zero_results: zero_results.to_s,
            source: clamp_source(source)
          )
        end

        # clamp_scope here too: every current caller passes a SearchService-derived
        # scope, but nothing enforces that at this boundary, and click_search_result's
        # label is clamped for the same unbounded-cardinality reason.
        def record_result_click(search_type:, scope:, position:)
          result_clicks_counter.increment(
            search_type: clamp_search_type(search_type),
            scope: clamp_scope(scope),
            position_bucket: position_bucket(position)
          )
        end

        private

        def requests_counter
          Gitlab::Metrics.counter(
            :gitlab_global_search_requests_total,
            'Total number of Global Search requests, labelled by search_type, scope, zero_results, and source'
          )
        end
        strong_memoize_attr :requests_counter

        def result_clicks_counter
          Gitlab::Metrics.counter(
            :gitlab_global_search_result_clicks_total,
            'Total number of Global Search result clicks, labelled by search_type, scope, and position_bucket'
          )
        end
        strong_memoize_attr :result_clicks_counter

        # recorded_search_types, not SearchService.supported_search_types directly:
        # clicks on semantic-code-search results carry 'search_type: semantic',
        # which SearchService never returns, so clamp_search_type nils it out.
        def recorded_search_types
          ::SearchService.supported_search_types
        end

        def clamp_search_type(search_type)
          search_type.presence_in(recorded_search_types)
        end

        def clamp_scope(scope)
          scope.presence_in(::Search::Scopes.all_scope_names)
        end

        def clamp_source(source)
          source.to_s.presence_in(SOURCES)
        end

        def position_bucket(position)
          return DEFAULT_POSITION_BUCKET unless position.is_a?(Numeric) && position >= 1

          position = position.to_i

          POSITION_BUCKETS.each do |range, bucket|
            return bucket if range.cover?(position)
          end

          DEFAULT_POSITION_BUCKET
        end
      end
    end
  end
end

Gitlab::Metrics::GlobalSearchRelevancyCounters.prepend_mod

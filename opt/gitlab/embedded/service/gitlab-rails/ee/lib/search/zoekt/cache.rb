# frozen_string_literal: true

module Search
  module Zoekt
    class Cache
      extend NumbersHelper

      MAX_PAGES = 10
      EXPIRES_IN = 5.minutes

      def self.humanize_expires_in
        parts = EXPIRES_IN.parts
        unit = parts.each_key.first
        number = parts.each_value.first
        "#{number_in_words(number)} #{unit}"
      end

      def initialize(query, **options)
        @query = query
        @current_user = options.fetch(:current_user)
        @project_id = options.fetch(:project_id)
        @group_id = options.fetch(:group_id)
        @per_page = options.fetch(:per_page)
        @current_page = options.fetch(:page)
        @max_per_page = options.fetch(:max_per_page)
        @search_mode = options.fetch(:search_mode)
        @chunk_size = options.fetch(:chunk_size)
        @filters = options.fetch(:filters)
        @count_only = options.fetch(:count_only)
        @known_languages = options.fetch(:known_languages, [])
      end

      def fetch
        return yield page_limit unless enabled?

        search_results, total_count, file_count = read_cache

        unless search_results
          search_results, total_count, file_count = yield page_limit

          update_cache!(search_results: search_results, total_count: total_count, file_count: file_count)
        end

        [search_results, total_count, file_count]
      end

      private

      attr_reader :current_user, :query, :project_id, :group_id, :per_page, :current_page, :max_per_page, :search_mode,
        :chunk_size, :filters, :count_only, :known_languages

      def enabled?
        return false unless Gitlab::CurrentSettings.zoekt_cache_response?
        # When offset pagination is active, pages beyond MAX_PAGES are fetched as a
        # single-page slice - bypass the cache entirely to avoid polluting the batch
        # cache entries for pages 1-MAX_PAGES with a partial result.
        return false if current_page > MAX_PAGES && ::Search::Zoekt::OffsetPagination.active?

        (project_id.present? || group_id.present?) && per_page <= max_per_page
      end

      def cache_key(page: current_page)
        user_id = current_user&.id || 0
        # We need to use {user_id} as part of the key for Redis Cluster support
        "cache:zoekt:{#{user_id}}/#{count_only}/#{search_fingerprint}/#{per_page}/#{page}"
      end

      def with_redis(&block)
        Gitlab::Redis::Cache.with(&block) # rubocop:disable CodeReuse/ActiveRecord -- this has nothing to do with AR
      end

      def page_limit
        return [current_page, MAX_PAGES].max if enabled?

        current_page
      end

      def search_fingerprint
        scope_key = "g#{group_id}-p#{project_id}"
        filters_key = Gitlab::Json.generate(filters.sort)
        languages_key = Gitlab::Json.generate(known_languages.sort)
        data = "#{query}-#{scope_key}-#{search_mode}-#{chunk_size}-#{filters_key}-#{languages_key}"
        OpenSSL::Digest.hexdigest('SHA256', data)
      end

      def read_cache
        data = with_redis do |redis|
          redis.get(cache_key)
        end

        return unless data

        Marshal.load(data) # rubocop:disable Security/MarshalLoad -- We're loading data we saved below (similar to Rails.cache)
      end

      def update_cache!(search_results:, total_count:, file_count:)
        # For count-only queries, file_count is 0, but we still want to cache the count
        return if !count_only && file_count == 0

        with_redis do |redis|
          redis.multi do |pipeline|
            (0..MAX_PAGES).each do |page_idx|
              result = search_results[page_idx]
              # For count-only queries, result will be nil/empty, but we still want to cache page 0
              next unless result || (count_only && page_idx == 0)

              cached_result = [{ page_idx => result }, total_count, file_count]

              key = cache_key(page: page_idx + 1)
              pipeline.set(key, Marshal.dump(cached_result), ex: EXPIRES_IN)
            end
          end
        end
      end
    end
  end
end

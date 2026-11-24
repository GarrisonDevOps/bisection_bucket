# frozen_string_literal: true

module Search
  module Zoekt
    class Query
      include Gitlab::Utils::StrongMemoize

      EXACT_SYNTAX_FILTERS = %w[c case f file lang sym].freeze
      SUPPORTED_SYNTAX_FILTERS = (
        EXACT_SYNTAX_FILTERS + AdvancedCodeSearchFilterTranspiler::ADVANCED_CODE_SEARCH_FILTERS
      ).freeze

      attr_reader :query, :source

      def initialize(query, source: nil)
        raise ArgumentError, 'query argument can not be nil' unless query

        @source = source&.to_sym
        @query = query
      end

      def formatted_query(search_mode)
        term = case search_mode.to_sym
               when :exact then RE2::Regexp.escape(keyword)
               when :regex then keyword
               else raise ArgumentError, 'Not a valid search_mode'
               end
        return term if filters.empty?

        transformed_filters = filters.map do |filter|
          next filter unless source == :api # transpilation is supported only for api

          AdvancedCodeSearchFilterTranspiler.new(filter).transpile
        end

        term.present? ? "#{term} #{transformed_filters.join(' ')}" : transformed_filters.join(' ')
      end

      private

      def keyword
        query.gsub(query_matcher_regex, '').strip
      end

      def filters
        @filters ||= query.scan(query_matcher_regex).flatten
      end

      def query_matcher_regex
        Regexp.union(available_syntax_filters.map { |filter| /-?#{filter}:\S+/ })
      end
      strong_memoize_attr(:query_matcher_regex)

      def available_syntax_filters
        extra = ::Search::Zoekt.feature_available?(:repo_filter_search) ? %w[repo] : []
        SUPPORTED_SYNTAX_FILTERS + extra
      end
      strong_memoize_attr(:available_syntax_filters)
    end
  end
end

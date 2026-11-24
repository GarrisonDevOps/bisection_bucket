# frozen_string_literal: true

module Search
  module Elastic
    class Relation
      # Elasticsearch substitutes a sentinel for a missing value when sorting, chosen by the field's
      # numeric comparator rather than its declared range. Elasticsearch 8.19 and 9.1 moved byte,
      # short and integer onto the int comparator, so both widths have to be recognised.
      ELASTICSEARCH_LONG_MAX_VALUE = 9223372036854775807
      ELASTICSEARCH_LONG_MIN_VALUE = -9223372036854775808
      ELASTICSEARCH_INT_MAX_VALUE = 2147483647
      ELASTICSEARCH_INT_MIN_VALUE = -2147483648

      MISSING_SORT_VALUES = [
        ELASTICSEARCH_LONG_MAX_VALUE,
        ELASTICSEARCH_LONG_MIN_VALUE,
        ELASTICSEARCH_INT_MAX_VALUE,
        ELASTICSEARCH_INT_MIN_VALUE
      ].freeze

      def initialize(klass, query, options)
        @klass = klass
        @query = query
        @options = options
        @preload_values = []
      end

      def before(...)
        paginator.before(...)

        self
      end

      def after(...)
        paginator.after(...)

        self
      end

      def first(limit)
        paginator.first(limit)

        records
      end

      def last(limit)
        paginator.last(limit)

        records.reverse
      end

      def cursor_for(record)
        # Pagination sorts by [sort property, tie breaker] and branches on a nil sort value to build
        # its missing-value filter. The tie breaker is a non-null long id that legitimately reaches
        # these magnitudes, so converting it would strand the cursor rather than repair it.
        sort_value, tie_breaker_value = hit_for(record)['sort']

        [MISSING_SORT_VALUES.include?(sort_value) ? nil : sort_value, tie_breaker_value]
      end

      def preload(*preloads)
        @preload_values += preloads

        self
      end

      def to_a
        records
      end

      def size
        response_mapper.total_count
      end

      private

      attr_reader :klass, :query, :options, :preload_values

      delegate :records, to: :response_mapper, private: true
      delegate :query_hash, to: :paginator, private: true

      def response_mapper
        @response_mapper ||= ::Gitlab::Search::Client.execute_search(query: query_hash, options: options) do |response|
          ::Search::Elastic::ResponseMapper.new(response, response_mapper_options)
        end
      end

      def response_mapper_options
        { klass: klass, preloads: preload_values, primary_key: primary_key }
      end

      def paginator
        @paginator ||= Pagination.new(query, primary_key)
      end

      # Must be included in the query's `source_fields`, since both #records and #hit_for read it
      # from `_source`. The document `_id` is unusable here: it is the indexed reference's
      # identifier, which for sbom_occurrence_refs is the ref id rather than the occurrence id.
      def primary_key
        @primary_key ||= options[:primary_key] || :id
      end

      def hit_for(record)
        response_mapper.results.find { |result| result.dig('_source', primary_key).to_i == record.id }
      end
    end
  end
end

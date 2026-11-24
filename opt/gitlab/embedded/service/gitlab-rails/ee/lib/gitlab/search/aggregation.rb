# frozen_string_literal: true

module Gitlab
  module Search
    class Aggregation
      attr_reader :name, :buckets

      def initialize(name, elastic_aggregation_buckets)
        @name = name
        @buckets = parse_buckets(elastic_aggregation_buckets)
      end

      private

      def parse_buckets(buckets)
        return [] unless buckets

        buckets.map do |b|
          result = { key: b['key_as_string'] || b['key'], count: b['doc_count'] }
                     .merge(b['extra']&.symbolize_keys || {})

          # Process nested aggregations
          nested_aggs = {}
          b.each do |key, value|
            next unless value.is_a?(Hash) && value['buckets'].is_a?(Array)

            nested_aggs[key.to_sym] = Aggregation.new(key, value['buckets']).buckets
          end

          result[:buckets] = nested_aggs unless nested_aggs.empty?
          result
        end
      end
    end
  end
end

# frozen_string_literal: true

# This implementation assumes that there will always be
# a single sort property in the query already.
module Search
  module Elastic
    class Pagination
      include Search::Elastic::Concerns::FilterUtils

      # `_last` matches the Elasticsearch default, so forward ordering is unchanged.
      MISSING_LAST = '_last'
      MISSING_FIRST = '_first'

      attr_reader :query_hash

      def initialize(query_hash, default_tie_breaker_property = :id)
        @query_hash = query_hash.deep_dup
        @sort_property_value = nil
        @default_tie_breaker_property = default_tie_breaker_property
        @tie_breaker_property_value = nil
        @original_sort = query_hash[:sort]
      end

      def after(sort_property_value, tie_breaker_property_value)
        @sort_property_value = sort_property_value
        @tie_breaker_property_value = tie_breaker_property_value
        @is_after = true

        self
      end

      def before(sort_property_value, tie_breaker_property_value)
        @sort_property_value = sort_property_value
        @tie_breaker_property_value = tie_breaker_property_value

        self
      end

      def first(size)
        order

        query_hash[:size] = size

        paginate
      end

      def last(size)
        reverse_order

        query_hash[:size] = size

        paginate
      end

      def paginate
        # Allow nil sort_property_value (for null values in ES), but require tie_breaker to be set
        return query_hash if tie_breaker_property_value.nil?

        add_filter(query_hash, :query, :bool, :filter) do
          pagination_filter
        end
      end

      private

      attr_reader :sort_property_value,
        :default_tie_breaker_property,
        :tie_breaker_property_value,
        :original_sort,
        :is_after

      def pagination_filter
        # When the sort property value is nil, we're paginating past records with null values.
        # Elasticsearch sorts nulls last (using Long.MAX_VALUE internally), so we need special handling.
        return pagination_filter_for_null_cursor if sort_property_value.nil?

        pagination_filter_for_non_null_cursor
      end

      def pagination_filter_for_null_cursor
        # Cursor is [nil, tie_breaker_value], meaning we've reached null values in the sort field.
        null_sort_values = {
          bool: {
            must: [
              { bool: { must_not: { exists: { field: sort_property } } } },
              {
                range: {
                  tie_breaker_property => {
                    document_matching_operator(tie_breaker_sort_direction) => tie_breaker_property_value
                  }
                }
              }
            ]
          }
        }

        # Paginating forward, only the remaining null-sort documents follow the cursor.
        return null_sort_values if is_after

        # Paginating backward, every non-null document precedes the cursor because Elasticsearch
        # sorts nulls last, so filtering to null-sort documents alone would drop the previous page.
        {
          bool: {
            should: [null_sort_values, { exists: { field: sort_property } }],
            minimum_should_match: 1
          }
        }
      end

      def pagination_filter_for_non_null_cursor
        # Standard cursor: [sort_value, tie_breaker_value]
        # Match records where:
        # 1. sort_property > cursor_value, OR
        # 2. sort_property = cursor_value AND tie_breaker > cursor_tie_breaker
        # 3. PLUS: If sorting ascending, include null values (they sort after non-nulls)
        should_clauses = [
          {
            range: {
              sort_property => {
                document_matching_operator(sort_direction) => sort_property_value
              }
            }
          },
          {
            bool: {
              must: [
                {
                  term: {
                    sort_property => sort_property_value
                  }
                },
                {
                  range: {
                    tie_breaker_property => {
                      document_matching_operator(tie_breaker_sort_direction) => tie_breaker_property_value
                    }
                  }
                }
              ]
            }
          }
        ]

        # When paginating forward (after), include records with null sort values.
        # Elasticsearch always sorts nulls last, regardless of ASC/DESC order:
        # - ASC: 1, 2, 3, null, null (nulls after max value)
        # - DESC: 3, 2, 1, null, null (nulls still after in iteration order)
        # So forward pagination from any non-null value should capture nulls.
        should_clauses << { bool: { must_not: { exists: { field: sort_property } } } } if is_after

        { bool: { should: should_clauses } }
      end

      def sort_property
        @sort_property ||= original_sort.each_key.first
      end

      def sort_value
        @sort_value ||= original_sort.each_value.first
      end

      def sort_direction
        @sort_direction ||= sort_value[:order].to_sym
      end

      def tie_breaker_property
        @tie_breaker_property ||= original_sort.keys.second || default_tie_breaker_property
      end

      def tie_breaker_sort_value
        @tie_breaker_sort_value ||= original_sort.values.second || sort_value
      end

      def tie_breaker_sort_direction
        @tie_breaker_sort_direction ||= tie_breaker_sort_value[:order].to_sym
      end

      def order
        query_hash[:sort] = [
          { sort_property => sort_value.merge(order: sort_direction, missing: MISSING_LAST) },
          { tie_breaker_property => { order: tie_breaker_sort_direction, missing: MISSING_LAST } }
        ]
      end

      # Elasticsearch defaults `missing` to last in *both* directions, which makes reversing the sort
      # not a true reversal: ascending [1, 2, nil] would reverse to [2, 1, nil] instead of
      # [nil, 2, 1], so `#last` could never reach the missing bucket. Flipping `missing` alongside
      # the order is what lets a backward page span the boundary between present and missing values.
      def reverse_order
        query_hash[:sort] = [
          { sort_property => sort_value.merge(order: reverse_sort_direction(sort_direction),
            missing: MISSING_FIRST) },
          { tie_breaker_property => { order: reverse_sort_direction(tie_breaker_sort_direction),
                                      missing: MISSING_FIRST } }
        ]
      end

      def document_matching_operator(direction)
        if direction == :asc
          is_after ? :gt : :lt
        else
          is_after ? :lt : :gt
        end
      end

      def reverse_sort_direction(direction)
        direction == :asc ? :desc : :asc
      end
    end
  end
end

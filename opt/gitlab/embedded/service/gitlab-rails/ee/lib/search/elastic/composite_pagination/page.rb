# frozen_string_literal: true

module Search
  module Elastic
    module CompositePagination
      # One page of a composite aggregation. Enumerable over the records, so a caller that does
      # not paginate can treat it as the list and ignore the rest.
      #
      # The keys are the retained buckets', not the `after_key` Elasticsearch returns: that one
      # belongs to the probe bucket, so a cursor built from it would skip a row per page.
      class Page
        include Enumerable

        attr_reader :records, :first_key, :last_key

        def initialize(records: [], first_key: nil, last_key: nil, has_next_page: false)
          @records = records
          @first_key = first_key
          @last_key = last_key
          @has_next_page = has_next_page
        end

        def has_next_page?
          @has_next_page
        end

        delegate :each, :size, :empty?, :any?, to: :records
      end
    end
  end
end

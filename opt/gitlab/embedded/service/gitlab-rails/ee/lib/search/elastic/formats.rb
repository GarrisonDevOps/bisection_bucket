# frozen_string_literal: true

module Search
  module Elastic
    module Formats
      class << self
        def size(query_hash:, options:)
          return query_hash unless options[:count_only] || options[:per_page]

          size = options[:count_only] ? 0 : options[:per_page]
          query_hash.merge(size: size)
        end

        def source_fields(query_hash:, options:)
          return query_hash unless options[:source_fields]

          query_hash.merge(_source: options[:source_fields])
        end

        def collapse(query_hash:, options:)
          return query_hash unless options[:collapse_field]

          query_hash.merge(collapse: { field: options[:collapse_field] })
        end

        def page(query_hash:, options:)
          return query_hash unless options[:page] && options[:per_page]

          from = options[:per_page] * (options[:page] - 1)
          query_hash.merge(from: from)
        end
      end
    end
  end
end

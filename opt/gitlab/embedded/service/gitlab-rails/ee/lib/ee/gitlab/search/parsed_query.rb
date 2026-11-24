# frozen_string_literal: true

module EE
  module Gitlab
    module Search
      module ParsedQuery
        def elasticsearch_filter_context(object)
          {
            filter: including_filters.map { |f| build_elasticsearch_filter_clause(object, f) },
            must_not: excluding_filters.map { |f| build_elasticsearch_filter_clause(object, f) }
          }
        end

        private

        def build_elasticsearch_filter_clause(object, filter)
          type = filter.fetch(:type, :wildcard)
          field = filter.fetch(:field, filter[:name])

          field_name = object.present? ? "#{object}.#{field}" : field.to_s

          {
            type => {
              field_name => filter[:value]
            }
          }
        end
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Elastic
    module Scores
      class << self
        # Wraps query_hash in a function_score query using options[:score_functions].
        # No-op when score_functions is absent or a field sort is applied
        # (sort: present means _score is unused).
        def wrap(query_hash:, options:)
          return query_hash if options[:score_functions].blank?
          return query_hash if query_hash[:sort].present?

          query_hash.except(:query).merge(
            query: {
              function_score: {
                query: query_hash[:query],
                functions: options[:score_functions],
                score_mode: 'multiply',
                boost_mode: 'multiply'
              }
            }
          )
        end

        # Boosts by a numeric field using ln2p (ln(2+value)), giving ~0.69 at 0.
        def field_value_function(field:, modifier: 'ln2p')
          { field_value_factor: { field: field, modifier: modifier, missing: 0 } }
        end

        # Applies a flat score multiplier to documents matching filter.
        def filter_weight_function(filter:, weight:)
          { filter: filter, weight: weight }
        end
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Elastic
    module Sorts
      class Group < Base
        base_sorts_wrapped = Base::SORT_MAPPINGS.transform_values { |v| [v] }

        SORT_MAPPINGS = base_sorts_wrapped.merge(
          similarity: ['_score']
        ).freeze
      end
    end
  end
end

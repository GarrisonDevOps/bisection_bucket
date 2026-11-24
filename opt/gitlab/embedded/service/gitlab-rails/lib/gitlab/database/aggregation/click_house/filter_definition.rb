# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      module ClickHouse
        class FilterDefinition < PartDefinition
          include FilterValidators

          def initialize(name, type, expression = nil, **kwargs)
            super
            @merge_column = kwargs[:merge_column]
          end

          def apply_inner(query_builder, filter_config)
            apply(query_builder, filter_config)
          end

          def metric?
            false
          end

          private

          def merge_column?
            !!@merge_column
          end

          def column(query_builder)
            expression&.call || query_builder.table[name]
          end

          def apply(_query_builder, _filter_config)
            raise NoMethodError
          end
        end
      end
    end
  end
end

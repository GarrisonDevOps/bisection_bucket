# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      module ActiveRecord
        class FilterDefinition < PartDefinition
          include FilterValidators

          def apply(_relation, _filter_config)
            raise NoMethodError
          end

          private

          def column(relation)
            expression&.call || relation.arel_table[name]
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Database
    module Aggregation
      class QueryPlan
        class Filter < BasePart
          # Values as given in the request. The formatter can drop values it does not
          # recognize, so validation must run against these rather than the formatted ones.
          attr_reader :raw_values

          def initialize(definition, configuration, query_plan:)
            @raw_values = configuration[:values]
            super(definition, format_configuration(definition, configuration), query_plan: query_plan)
          end

          # Values after the formatter, the ones the query uses.
          def values
            configuration[:values]
          end

          private

          def format_configuration(definition, configuration)
            return configuration unless definition&.formatter

            configuration.merge(values: definition.formatter.call(configuration[:values]))
          end
        end
      end
    end
  end
end

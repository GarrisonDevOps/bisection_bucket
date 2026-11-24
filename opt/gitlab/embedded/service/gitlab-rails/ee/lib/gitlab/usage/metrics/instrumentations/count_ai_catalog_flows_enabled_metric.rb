# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountAiCatalogFlowsEnabledMetric < DatabaseMetric
          operation :count

          def initialize(metric_definition)
            super

            return if consumer_type.nil? || consumer_type.in?(valid_consumer_types)

            raise ArgumentError, "consumer_type '#{consumer_type}' must be one of: #{valid_consumer_types.join(', ')}"
          end

          relation { ::Ai::Catalog::ItemConsumer.where(enabled: true) }

          private

          def relation
            scope = super

            case consumer_type
            when :group
              scope.where.not(group: nil)
            when :project
              scope.where.not(project: nil)
            else
              scope
            end
          end

          def consumer_type
            options[:consumer_type]&.to_sym
          end

          def valid_consumer_types
            [:group, :project]
          end
        end
      end
    end
  end
end

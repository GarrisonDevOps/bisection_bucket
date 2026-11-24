# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountAiCatalogItemsMetric < DatabaseMetric
          operation :count

          def initialize(metric_definition)
            super

            return if item_type.nil? || item_type.in?(allowed_item_types)

            raise ArgumentError, "item_type '#{item_type}' must be one of: #{allowed_item_types.join(', ')}"
          end

          relation { ::Ai::Catalog::Item }

          private

          def relation
            scope = super
            scope = scope.where(item_type: item_type) unless item_type.nil?
            scope = scope.where(visibility: visibility) unless visibility.nil?
            scope
          end

          def item_type
            options[:item_type]&.to_s
          end

          def visibility
            options[:visibility]&.to_s
          end

          def allowed_item_types
            ::Ai::Catalog::Item.item_types.keys.map(&:to_s)
          end
        end
      end
    end
  end
end

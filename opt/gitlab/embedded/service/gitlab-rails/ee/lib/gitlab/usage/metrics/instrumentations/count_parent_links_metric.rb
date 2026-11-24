# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountParentLinksMetric < DatabaseMetric
          operation :count
          start { ::WorkItems::ParentLink.minimum(:id) }
          finish { ::WorkItems::ParentLink.maximum(:id) }
          metric_options do
            {
              batch_size: 10_000
            }
          end

          def initialize(metric_definition)
            super

            raise ArgumentError, "valid parent_type options attribute is required" unless parent_type.present?
          end

          def relation
            ::WorkItems::ParentLink
             .joins(:work_item_parent)
             .where(work_item_parent: { work_item_type_id: parent_type.id })
          end

          private

          def parent_type
            ::WorkItems::TypesFramework::Provider.new.find_by_base_type(options[:parent_type])
          end
        end
      end
    end
  end
end

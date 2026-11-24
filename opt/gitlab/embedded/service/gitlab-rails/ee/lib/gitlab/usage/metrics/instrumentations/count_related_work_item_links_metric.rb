# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountRelatedWorkItemLinksMetric < DatabaseMetric
          operation :count
          start { ::WorkItems::RelatedWorkItemLink.minimum(:id) }
          finish { ::WorkItems::RelatedWorkItemLink.maximum(:id) }
          metric_options do
            {
              batch_size: 10_000
            }
          end

          def initialize(metric_definition)
            super

            raise ArgumentError, "valid target_type options attribute is required" unless target_type.present?
          end

          def relation
            ::WorkItems::RelatedWorkItemLink
              .joins(:target)
              .where(target: { work_item_type_id: target_type.id })
          end

          private

          def target_type
            ::WorkItems::TypesFramework::Provider.new.find_by_base_type(options[:target_type])
          end
        end
      end
    end
  end
end

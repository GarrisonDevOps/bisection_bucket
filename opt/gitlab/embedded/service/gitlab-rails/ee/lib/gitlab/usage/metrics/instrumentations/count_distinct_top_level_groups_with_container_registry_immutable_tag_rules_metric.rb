# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountDistinctTopLevelGroupsWithContainerRegistryImmutableTagRulesMetric < DatabaseMetric
          operation :distinct_count, column: 'root_namespaces.id'

          relation do
            ::ContainerRegistry::Protection::TagRule
              .immutable
              .joins(project: :namespace)
              .joins("INNER JOIN namespaces AS root_namespaces ON root_namespaces.id = namespaces.traversal_ids[1]")
              .where("root_namespaces.type = 'Group' AND root_namespaces.parent_id IS NULL")
          end
        end
      end
    end
  end
end

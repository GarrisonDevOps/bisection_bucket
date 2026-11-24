# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Returns a hash of { flow_reference => count_of_groups_with_flow_enabled }.
        #
        # A flow is considered enabled for a namespace when its reference appears in
        # namespace_settings.enabled_foundational_flows.
        #
        # New flows defined in Ai::Catalog::FoundationalFlow are automatically included.
        class FoundationalFlowEnabledCountsMetric < GenericMetric
          value do
            counts_by_reference = ::Ai::Catalog::EnabledFoundationalFlow
              .joins(:catalog_item)
              .merge(::Ai::Catalog::Item.foundational_flows)
              .where.not(namespace_id: nil)
              .group('ai_catalog_items.foundational_flow_reference')
              .count

            ::Ai::Catalog::FoundationalFlow.all
              .each_with_object({}) do |flow, result|
                result[flow.foundational_flow_reference] =
                  counts_by_reference[flow.foundational_flow_reference] || 0
              end
          end
        end
      end
    end
  end
end

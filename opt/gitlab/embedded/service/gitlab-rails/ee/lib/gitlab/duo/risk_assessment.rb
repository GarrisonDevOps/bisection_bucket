# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module_function

      def available?(project)
        ::Gitlab::SafeRequestStore.fetch([:risk_assessment_available, project.id]) do
          flow = ::Ai::Catalog::FoundationalFlow.risk_classification_v1

          next false if flow&.blocked_for?(project.root_ancestor)
          next false unless project.duo_foundational_flows_enabled
          next false unless project.enabled_flow_catalog_item_ids.include?(flow&.catalog_item&.id)

          ::Gitlab::Llm::StageCheck.available?(project, :duo_workflow)
        end
      end
    end
  end
end

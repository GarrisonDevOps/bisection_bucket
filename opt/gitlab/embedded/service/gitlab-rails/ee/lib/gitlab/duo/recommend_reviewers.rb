# frozen_string_literal: true

module Gitlab
  module Duo
    module RecommendReviewers
      module_function

      def available?(project)
        ::Gitlab::SafeRequestStore.fetch([:recommend_reviewers_available, project.id]) do
          next false unless project.duo_foundational_flows_enabled

          flow = ::Ai::Catalog::FoundationalFlow.recommend_reviewers_v1
          next false unless project.enabled_flow_catalog_item_ids.include?(flow&.catalog_item&.id)

          ::Gitlab::Llm::StageCheck.available?(project, :duo_workflow)
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Analytics
    module Aggregation
      module ImplicitSourcesFinder
        extend ::Gitlab::Utils::Override

        private

        override :filter_groups
        def filter_groups(groups)
          by_duo_agent_platform_enabled(super)
        end

        def by_duo_agent_platform_enabled(groups)
          return groups unless params[:with_duo_agent_platform_enabled]
          return groups.with_duo_agent_platform_enabled if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          ::Ai::DuoWorkflow.duo_agent_platform_available? ? groups : groups.none
        end
      end
    end
  end
end

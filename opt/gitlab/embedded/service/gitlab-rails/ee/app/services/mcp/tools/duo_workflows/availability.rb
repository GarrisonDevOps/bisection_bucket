# frozen_string_literal: true

module Mcp
  module Tools
    module DuoWorkflows
      module Availability
        def available?(current_user)
          return false unless current_user

          ::Gitlab::SafeRequestStore.fetch([:mcp_duo_agent_platform_tools_available, current_user.id]) do
            duo_agent_platform_available?(current_user)
          end
        end

        private

        def duo_agent_platform_available?(user)
          !::Gitlab::CurrentSettings.duo_never_on? &&
            (::License.feature_available?(:ai_workflows) ||
              ::GitlabSubscriptions::Duo.active_self_managed_gitlab_credits?) &&
            ::Ai::Catalog.duo_agent_platform_available_for_user?(user) &&
            user.allowed_to_use?(:duo_agent_platform)
        end
      end
    end
  end
end

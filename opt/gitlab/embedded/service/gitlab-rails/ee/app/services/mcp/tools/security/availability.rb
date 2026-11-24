# frozen_string_literal: true

module Mcp
  module Tools
    module Security
      module Availability
        def available?(current_user)
          return false unless current_user

          ::Gitlab::SafeRequestStore.fetch([:mcp_security_tools_available, licensed_feature, current_user.id]) do
            licensed_feature_available_for_user?(current_user)
          end
        end

        private

        def licensed_feature
          :security_dashboard
        end

        # On GitLab.com the instance license covers every plan, so the user also needs
        # a top-level group whose plan includes the feature.
        def licensed_feature_available_for_user?(user)
          return false unless ::License.feature_available?(licensed_feature)
          return true unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          ::Namespace.id_in(::Ai::UserAuthorizer.for(user).gitlab_com_root_group_ids)
            .with_feature_available_in_plan(licensed_feature)
            .exists?
        end
      end
    end
  end
end

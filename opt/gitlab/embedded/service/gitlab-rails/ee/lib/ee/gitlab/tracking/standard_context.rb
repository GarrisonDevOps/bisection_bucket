# frozen_string_literal: true

module EE
  module Gitlab
    module Tracking
      module StandardContext
        extend ::Gitlab::Utils::Override

        override :get_plan_name
        def get_plan_name(namespace)
          # namespace&.actual_plan_name always returns 'default' when not on gitlab.com
          return namespace&.actual_plan_name if ::Gitlab.com?

          ::License.current&.plan || super
        end

        override :gitlab_team_member?
        def gitlab_team_member?(user_id)
          return unless ::Gitlab.com?
          return unless user_id

          ::Gitlab::Com.gitlab_com_group_member?(user_id)
        end

        private

        override :realm
        def realm
          ::CloudConnector.gitlab_realm
        end

        override :deployment_type
        def deployment_type
          ::CloudConnector.deployment_type
        end

        override :tracked_user_id
        def tracked_user_id
          return unless user.is_a? User

          ::Gitlab.com? ? user.id : ::Gitlab::CryptoHelper.sha256(user.id)
        end
      end
    end
  end
end

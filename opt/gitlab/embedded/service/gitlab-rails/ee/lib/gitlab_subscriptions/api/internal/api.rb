# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      class API < ::API::Base
        helpers GitlabSubscriptions::API::Internal::Helpers

        namespace do
          before do
            authenticate_from_jwt!
          end

          mount ::GitlabSubscriptions::API::Internal::AddOnPurchases
          mount ::GitlabSubscriptions::API::Internal::ComputeMinutes
          mount ::GitlabSubscriptions::API::Internal::Members
          mount ::GitlabSubscriptions::API::Internal::Namespaces
          mount ::GitlabSubscriptions::API::Internal::Namespaces::Provision
          mount ::GitlabSubscriptions::API::Internal::NamespaceProjects
          mount ::GitlabSubscriptions::API::Internal::Subscriptions
          mount ::GitlabSubscriptions::API::Internal::UpcomingReconciliations
          mount ::GitlabSubscriptions::API::Internal::Users
        end

        namespace do
          before do
            if jwt_request?
              authenticate_from_jwt!
            else
              authenticated_as_admin!
            end
          end

          # These APIs have been migrated to follow the internal subscriptions path,
          # 'internal/gitlab_subscriptions', in https://gitlab.com/gitlab-org/gitlab/-/issues/463741.
          # They will be removed in https://gitlab.com/gitlab-org/gitlab/-/issues/473625.
          mount ::API::GitlabSubscriptions::AddOnPurchases
          mount ::API::Ci::Minutes
          mount ::API::GitlabSubscriptions::Subscriptions
        end
      end
    end
  end
end

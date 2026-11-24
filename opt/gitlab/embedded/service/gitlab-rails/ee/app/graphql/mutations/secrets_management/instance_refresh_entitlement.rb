# frozen_string_literal: true

module Mutations
  module SecretsManagement
    # Self-managed counterpart of `RefreshEntitlement`: admin-only, resolved
    # instance-wide (nil namespace).
    class InstanceRefreshEntitlement < BaseMutation
      graphql_name 'SecretsManagerInstanceRefreshEntitlement'

      # Refreshing is the first step of enabling the add-on, so it is granted to
      # exactly the users who may enable it; the `:global` subject selects the
      # admin-only GlobalPolicy rule.
      authorize :enable_secrets_manager_add_on

      authorize_granular_token permissions: [:enable_secrets_manager_add_on, :read_secrets_manager],
        boundary: :instance,
        boundary_type: :instance,
        assignable_when: [:admin, :self_managed]

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Instance-wide Secrets Manager entitlement state as the subscription service reports it now. ' \
          'Null when refreshing failed; see errors for the reason.'

      OFFLINE_ERROR = 'Refreshing the Secrets Manager entitlement requires an online cloud license.'
      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'

      def resolve
        authorize!(:global)

        # An offline license resolves from the local mirror, never CDot, so there is nothing to refresh.
        return { entitlement: nil, errors: [OFFLINE_ERROR] } if ::SecretsManagement::InstanceEnrollment.offline_license?

        if ::Gitlab::ApplicationRateLimiter.throttled?(:secrets_manager_entitlement_refresh,
          scope: { user: current_user })
          raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
        end

        entitlement = ::SecretsManagement::Entitlement.refresh!(nil, user: current_user)

        { entitlement: entitlement_adapter(entitlement), errors: [] }
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e)

        { entitlement: nil, errors: [UNAVAILABLE_ERROR] }
      end

      private

      def entitlement_adapter(entitlement)
        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: nil)
      end
    end
  end
end

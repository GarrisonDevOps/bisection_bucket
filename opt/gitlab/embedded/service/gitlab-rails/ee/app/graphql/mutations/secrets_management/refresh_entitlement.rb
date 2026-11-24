# frozen_string_literal: true

module Mutations
  module SecretsManagement
    # Re-asks the subscription service for the entitlement, bypassing its
    # cached answer, so billing consent given in the Customers Portal shows up
    # when the user acts on it. Self-managed: SecretsManagerInstanceRefreshEntitlement.
    class RefreshEntitlement < BaseMutation
      graphql_name 'SecretsManagerRefreshEntitlement'

      include Mutations::ResolvesGroup

      # Refreshing is the first step of enabling the add-on, so it is granted to
      # exactly the users who may enable it.
      authorize :enable_secrets_manager_add_on

      authorize_granular_token permissions: [:enable_secrets_manager_add_on, :read_secrets_manager],
        boundary_argument: :group_path,
        boundary_type: :group

      argument :group_path,
        GraphQL::Types::ID,
        required: true,
        description: 'Full path of the top-level group to refresh the Secrets Manager entitlement for.'

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Secrets Manager entitlement state as the subscription service reports it now. ' \
          'Null when the subscription service could not be reached; see errors.'

      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'

      def resolve(group_path:)
        group = authorized_find!(group_path: group_path)

        if ::Gitlab::ApplicationRateLimiter.throttled?(:secrets_manager_entitlement_refresh,
          scope: { user: current_user })
          raise_resource_not_available_error! ::Gitlab::ApplicationRateLimiter.throttled_error_message
        end

        entitlement = ::SecretsManagement::Entitlement.refresh!(group, user: current_user)

        {
          entitlement: ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: group),
          errors: []
        }
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: group.id)

        { entitlement: nil, errors: [UNAVAILABLE_ERROR] }
      end

      private

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end
    end
  end
end

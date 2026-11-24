# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    # The instance settings page has no group in context, so it cannot use
    # `Group.secretsManagerEntitlement`; a nil namespace resolves instance-wide.
    class InstanceEntitlementResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::SecretsManagement::EntitlementType, null: true
      description 'Instance-wide Secrets Manager entitlement on GitLab Self-Managed.'

      authorize :read_secrets_manager_entitlement

      def resolve
        authorize!(:global)

        entitlement = ::SecretsManagement::Entitlement.for(nil, user: current_user)

        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: nil)
      end
    end
  end
end

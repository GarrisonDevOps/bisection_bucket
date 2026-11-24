# frozen_string_literal: true

module SecretsManagement
  module SecretsPermissions
    module DeleteServiceHelpers
      extend ActiveSupport::Concern

      def execute(principal_id:, principal_type:)
        with_exclusive_lease_for(resource) do
          execute_delete_permission(principal_id: principal_id, principal_type: principal_type)
        end
      end

      private

      delegate :secrets_manager, to: :resource

      def execute_delete_permission(principal_id:, principal_type:)
        return secrets_manager_inactive_response unless secrets_manager&.active_after_refresh?
        return invalid_principal_response unless valid_principal?(principal_id, principal_type)

        policy_name = secrets_manager.policy_name_for_principal(
          principal_type: principal_type,
          principal_id: principal_id)

        api_policy_name = secrets_manager.api_policy_name_for_principal(
          principal_type: principal_type,
          principal_id: principal_id)

        delete_permission(policy_name, api_policy_name)
        expire_user_capabilities(principal_type, principal_id)

        ServiceResponse.success(payload: { secrets_permission: nil })
      end

      def delete_permission(policy_name, api_policy_name)
        # Delete the read-only API policy (value reads) first. If the second
        # delete fails, the worst-case orphan is the metadata-only management
        # policy, never lingering value-read access. Both deletes are idempotent,
        # so a failed call is cleaned up on retry.
        client.delete_policy(api_policy_name) if api_policy_name
        client.delete_policy(policy_name)
      end

      # Only a user grant maps to one cached capabilities entry; see `EffectiveCapabilitiesService.expire_for_user`.
      def expire_user_capabilities(principal_type, principal_id)
        return unless principal_type == SecretsManagement::BaseSecretsPermission::PRINCIPAL_TYPES[:user]

        UserPermissions::EffectiveCapabilitiesService.expire_for_user(
          secrets_manager: secrets_manager, user_id: principal_id.to_i
        )
      end

      def valid_principal?(principal_id, principal_type)
        return false if principal_id.blank? || principal_type.blank?

        valid_type = SecretsManagement::BaseSecretsPermission::VALID_PRINCIPAL_TYPES.include?(principal_type)
        valid_id = principal_id.to_s.match?(/\A\d+\z/)
        valid_type && valid_id
      end

      def invalid_principal_response
        ServiceResponse.error(message: 'Invalid principal')
      end
    end
  end
end

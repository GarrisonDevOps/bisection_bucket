# frozen_string_literal: true

module SecretsManagement
  module SecretsPermissions
    module UpdateServiceHelpers
      extend ActiveSupport::Concern

      def execute(principal_id:, principal_type:, actions:, expired_at:)
        with_exclusive_lease_for(resource) do
          execute_update_permission(
            principal_id: principal_id,
            principal_type: principal_type,
            actions: actions,
            expired_at: expired_at
          )
        end
      end

      private

      delegate :secrets_manager, to: :resource

      def execute_update_permission(principal_id:, principal_type:, actions:, expired_at:)
        secrets_permission = permission_class.new(
          principal_id: principal_id,
          principal_type: principal_type,
          actions: actions,
          granted_by: current_user.id,
          expired_at: expired_at,
          resource: resource
        )

        store_permission(secrets_permission)
      end

      def store_permission(secrets_permission)
        return error_response(secrets_permission) unless secrets_permission.valid?

        # Sequential writes with no rollback, by design. set_policy is a full
        # upsert and both writes are idempotent, so a partial failure is
        # recovered by retrying under the exclusive lease, which re-runs both and
        # converges. A rollback would only add more OpenBao calls that can
        # themselves fail, moving the failure window rather than closing it.
        store_management_policy(secrets_permission)
        store_api_policy(secrets_permission)
        expire_user_capabilities(secrets_permission.principal_type, secrets_permission.principal_id)

        ServiceResponse.success(payload: { secrets_permission: secrets_permission })
      rescue SecretsManagement::SecretsManagerClient::ApiError => e
        raise e unless e.message.include?('check-and-set parameter did not match the current version')

        secrets_permission.errors.add(:base, "Failed to save secrets_permission: #{e.message}")
        error_response(secrets_permission)
      end

      # Management policy (UI/user mount): metadata read, write, delete. Never
      # grants value reads.
      def store_management_policy(secrets_permission)
        secrets_manager = secrets_permission.secrets_manager
        policy_name = secrets_manager.policy_name_for_principal(
          principal_type: secrets_permission.principal_type,
          principal_id: secrets_permission.principal_id
        )

        policy = client.get_policy(policy_name) || AclPolicy.new(policy_name)

        update_policy_paths(
          policy,
          secrets_manager,
          secrets_permission.management_capabilities,
          secrets_permission.normalized_expired_at
        )

        client.set_policy(policy)
      end

      # Read-only API policy (API mount): value reads only, and only when
      # read_value is granted. Removed when read_value is not present.
      def store_api_policy(secrets_permission)
        secrets_manager = secrets_permission.secrets_manager
        policy_name = secrets_manager.api_policy_name_for_principal(
          principal_type: secrets_permission.principal_type,
          principal_id: secrets_permission.principal_id
        )

        caps = secrets_permission.api_capabilities
        if caps[:data].empty? && caps[:metadata].empty?
          client.delete_policy(policy_name) if policy_name
          return
        end

        policy = client.get_policy(policy_name) || AclPolicy.new(policy_name)
        update_policy_paths(policy, secrets_manager, caps, secrets_permission.normalized_expired_at)
        client.set_policy(policy)
      end

      def update_policy_paths(policy, secrets_manager, path_capabilities, expired_at)
        {
          secrets_manager.ci_full_path('*') => path_capabilities[:data],
          secrets_manager.ci_metadata_full_path('*') => path_capabilities[:metadata],
          secrets_manager.detailed_metadata_path('*') => path_capabilities[:detailed_metadata]
        }.each do |path, capabilities|
          # Kept even with no capabilities: the list service reads granted_by and
          # expired_at from these paths. An empty path grants nothing, but OpenBao uses
          # the most specific match, so it would shadow a broader glob added later.
          policy_path = policy.paths[path] ||= AclPolicyPath.new(path)
          policy_path.capabilities = Set.new(capabilities)
          policy_path.granted_by = current_user.id
          policy_path.expired_at = expired_at
        end
      end

      def error_response(secrets_permission)
        ServiceResponse.error(
          message: secrets_permission.errors.full_messages.to_sentence,
          payload: { secrets_permission: secrets_permission }
        )
      end

      # Only a user grant maps to one cached capabilities entry; see `EffectiveCapabilitiesService.expire_for_user`.
      def expire_user_capabilities(principal_type, principal_id)
        return unless principal_type == SecretsManagement::BaseSecretsPermission::PRINCIPAL_TYPES[:user]

        UserPermissions::EffectiveCapabilitiesService.expire_for_user(
          secrets_manager: secrets_manager, user_id: principal_id.to_i
        )
      end
    end
  end
end

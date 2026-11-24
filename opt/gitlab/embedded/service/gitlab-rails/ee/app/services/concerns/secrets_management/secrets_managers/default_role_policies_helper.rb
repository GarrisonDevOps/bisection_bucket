# frozen_string_literal: true

module SecretsManagement
  module SecretsManagers
    module DefaultRolePoliciesHelper
      extend ActiveSupport::Concern

      ROLE_PRINCIPAL_TYPE = 'Role'

      # Declared as permission actions so the capabilities come from the same
      # mapping the permissions UpdateService uses, and read back the same way.
      # Developer gets `create` rather than `write`, so a Developer can add a
      # secret but cannot change one that already exists.
      ROLE_ACTIONS = {
        Gitlab::Access::OWNER => %w[read write delete].freeze,
        Gitlab::Access::MAINTAINER => %w[read write].freeze,
        Gitlab::Access::DEVELOPER => %w[read create].freeze
      }.freeze

      private

      def create_default_role_policies
        default_roles.each do |access_level|
          policy_name = secrets_manager.policy_name_for_principal(
            principal_type: ROLE_PRINCIPAL_TYPE,
            principal_id: access_level
          )

          policy = SecretsManagement::AclPolicy.new(policy_name)
          update_policy_paths(policy, ROLE_ACTIONS.fetch(access_level))
          client.set_policy(policy)
        end
      end

      def update_policy_paths(policy, actions)
        caps = permission_class.new(actions: actions).management_capabilities

        caps[:data].each do |capability|
          policy.add_capability(secrets_manager.ci_full_path('*'), capability)
        end
        caps[:metadata].each do |capability|
          policy.add_capability(secrets_manager.ci_metadata_full_path('*'), capability)
        end
        caps[:detailed_metadata].each do |capability|
          policy.add_capability(secrets_manager.detailed_metadata_path('*'), capability)
        end
      end

      def secrets_manager
        raise NotImplementedError
      end

      # OpenBao client scoped to the secrets manager's namespace.
      def client
        raise NotImplementedError
      end

      def permission_class
        raise NotImplementedError
      end

      # Access levels to grant. Must be a subset of ROLE_ACTIONS keys, otherwise
      # `fetch` raises part way through, after earlier policies are written.
      def default_roles
        raise NotImplementedError
      end
    end
  end
end

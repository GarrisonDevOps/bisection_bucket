# frozen_string_literal: true

module SecretsManagement
  module SecretsPermissions
    module ListServiceHelpers
      extend ActiveSupport::Concern

      def execute
        return secrets_manager_inactive_response unless resource.secrets_manager&.active_after_refresh?

        secrets_permissions = list_secrets_permissions(resource)

        ServiceResponse.success(payload: { secrets_permissions: secrets_permissions })
      end

      private

      delegate :secrets_manager, to: :resource

      def list_secrets_permissions(resource)
        permissions = []

        # Read every read-only API policy up front so the loop below does not
        # issue one get_policy call to OpenBao per permission (an N+1).
        api_value_capabilities = api_value_capabilities_by_principal

        client.list_policies(type: :users) do |policy_data|
          policy_name = policy_data["key"]
          policy = policy_data["metadata"]

          # Extract principal information from policy name
          path_parts = policy_name.split('/')
          principal_type, principal_id = extract_principal_info_from_policy(path_parts)

          next unless principal_type && principal_id

          granted_by = nil
          expired_at = nil
          # Capabilities from the management policy, split by path.
          management_data = Set.new
          management_metadata = Set.new

          policy.paths.each do |path, path_obj|
            granted_by = path_obj.granted_by
            expired_at = path_obj.expired_at

            target = path.include?('/data/') ? management_data : management_metadata
            collect_valid_capabilities(path_obj, target)
          end

          # The read-only value capability lives in the separate API policy.
          api_data = api_value_capabilities.fetch([principal_type, principal_id], Set.new)

          # Create the permission object and set actions from capabilities
          permission = permission_class.new(
            resource: resource,
            principal_type: principal_type,
            principal_id: principal_id,
            granted_by: granted_by,
            expired_at: expired_at
          )
          permission.set_actions_from_capabilities(
            management_metadata: management_metadata,
            management_data: management_data,
            api_data: api_data
          )

          permissions << permission
        end

        permissions
      end

      def collect_valid_capabilities(path_obj, target)
        path_obj.capabilities.each do |capability|
          target.add(capability) if SecretsManagement::BaseSecretsPermission::VALID_CAPABILITIES.include?(capability)
        end
      end

      # Lists every read-only API policy in one call and maps the value-path
      # capabilities by [principal_type, principal_id]. The API policies live
      # under the `api/` prefix, mirroring the management policies under
      # `users/`, so stripping the prefix lets us reuse the same extraction.
      def api_value_capabilities_by_principal
        prefix = "#{SecretsManagement::SecretsManagers::ApiHelper::API_POLICY_PREFIX}/"
        capabilities = {}

        client.list_policies(type: "#{prefix}users") do |policy_data|
          policy_name = policy_data["key"]
          next unless policy_name.start_with?(prefix)

          path_parts = policy_name.delete_prefix(prefix).split('/')
          principal_type, principal_id = extract_principal_info_from_policy(path_parts)
          next unless principal_type && principal_id

          caps = Set.new
          policy_data["metadata"].paths.each do |path, path_obj|
            next unless path.include?('/data/')

            collect_valid_capabilities(path_obj, caps)
          end

          capabilities[[principal_type, principal_id]] = caps
        end

        capabilities
      end

      def extract_principal_info_from_policy(path_parts)
        # path_parts structure: ["users", TYPE, IDENTIFIER]
        return [nil, nil] if path_parts.size < 3

        case path_parts[1]
        when 'direct'
          if path_parts[2].start_with?('user_')
            ['User', path_parts[2].sub('user_', '').to_i]
          elsif path_parts[2].start_with?('member_role_')
            ['MemberRole', path_parts[2].sub('member_role_', '').to_i]
          end
        when 'roles'
          role_id = path_parts[2]
          role_id ? ['Role', role_id] : [nil, nil]
        end
      end
    end
  end
end

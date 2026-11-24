# frozen_string_literal: true

module SecretsManagement
  module SecretsManagers
    # Non-CI API access. Mirrors UserHelper but for a dedicated mount whose
    # policies are read-only (value reads). See UserHelper for the management
    # (UI) mount.
    module ApiHelper
      extend ActiveSupport::Concern

      API_POLICY_PREFIX = 'api'

      def api_auth_mount
        'api_jwt'
      end

      def api_auth_role
        'all_api'
      end

      def api_auth_type
        'jwt'
      end

      # Read-only policy name for a principal, parallel to the management policy
      # but under the `api/` prefix so the API mount's CEL can attach it on its
      # own.
      def api_policy_name_for_principal(principal_type:, principal_id:)
        name = policy_name_for_principal(principal_type: principal_type, principal_id: principal_id)
        return unless name

        [API_POLICY_PREFIX, name].join('/')
      end
    end
  end
end

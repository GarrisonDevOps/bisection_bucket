# frozen_string_literal: true

# rubocop: disable Gitlab/NamespacedClass -- nested in the legacy Gitlab::Shell class that verifies this JWT
module Gitlab
  class Shell
    # Verifies optional Gitlab-Shell-Api-Request JWT claims for Cells SSH-over-HTTP,
    # including the deploy-key lookup and the SSH certificate namespace.
    # Only build this from a payload already verified by Gitlab::Shell.verify_api_request.
    class ApiRequestClaims
      include Gitlab::Utils::StrongMemoize

      DEPLOY_KEY_TYPE = 'deploy_key'

      def initialize(payload)
        @payload = payload
      end

      def verify(user)
        return rejected(:invalid_check_ip) unless valid_check_ip?
        return rejected(:invalid_namespace_path) unless valid_namespace_path?
        return ServiceResponse.success unless deploy_key?
        return rejected(:invalid_gl_key_id) unless valid_gl_key_id?

        deploy_key = DeployKey.auth.find_by_id(raw_gl_key_id)
        return rejected(:deploy_key_not_found) unless deploy_key
        return rejected(:deploy_key_user_mismatch) unless deploy_key.user == user

        ServiceResponse.success(payload: { deploy_key: deploy_key })
      end

      def client_ip
        parsed_check_ip&.to_s
      end

      def namespace_path
        payload['namespace_path']
      end

      private

      attr_reader :payload

      def rejected(reason)
        ServiceResponse.error(
          message: 'Rejected Gitlab-Shell-Api-Request claims',
          reason: reason,
          payload: { gl_key_id: raw_gl_key_id }
        )
      end

      def deploy_key?
        payload['gl_key_type'] == DEPLOY_KEY_TYPE
      end

      def raw_gl_key_id
        payload['gl_key_id']
      end

      def valid_gl_key_id?
        raw_gl_key_id.is_a?(Integer) && raw_gl_key_id > 0
      end

      def check_ip
        payload['check_ip']
      end

      def valid_check_ip?
        check_ip.nil? || parsed_check_ip.present?
      end

      # gitlab-shell omits the claim for instance-wide certificates and plain keys.
      def valid_namespace_path?
        namespace_path.nil? || (namespace_path.is_a?(String) && namespace_path.present?)
      end

      # IPAddr.new also accepts CIDR ranges, which are not a client address.
      def parsed_check_ip
        return unless check_ip.is_a?(String) && check_ip.exclude?('/')

        IPAddr.new(check_ip)
      rescue IPAddr::Error
        nil
      end
      strong_memoize_attr :parsed_check_ip
    end
  end
end
# rubocop: enable Gitlab/NamespacedClass

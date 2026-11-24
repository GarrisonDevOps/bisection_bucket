# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    module JwtAuth
      include Gitlab::JwtAuthenticatable

      ISSUER = 'gitlab'
      AUDIENCE = 'gitlab-knowledge-graph'
      TOKEN_EXPIRE_TIME = 5.minutes
      # HS256 (symmetric) for now; asymmetric (ES256) is preferred per
      # https://docs.gitlab.com/development/secure_coding_guidelines/#working-securely-with-jwts
      # and will be investigated as a follow-up.
      ALGORITHM = 'HS256'

      class << self
        def secret_path
          Gitlab.config.knowledge_graph.secret_file
        end

        def ensure_secret!
          return if File.exist?(secret_path)

          write_secret
        rescue Errno::EACCES, Errno::EPERM, Errno::EROFS, Errno::ENOENT => e
          logger.warn(
            message: 'Could not write Knowledge Graph secret file',
            secret_path: secret_path,
            error: e.class.name,
            error_message: e.message
          )
        end

        def generate_token(user:, request_context:)
          return unless user

          start = ::Gitlab::Metrics::System.monotonic_time

          context = AuthorizationContext.for(user)

          payload = build_payload(
            context: context,
            current_time: Time.current.to_i,
            request_context: request_context
          )

          token = JWT.encode(payload, secret, ALGORITHM)
          duration = ::Gitlab::Metrics::System.monotonic_time - start
          ::Gitlab::Metrics::KnowledgeGraph::Request.observe_jwt_duration(duration)
          token
        rescue StandardError => e
          logger.error(
            message: 'Knowledge Graph JWT generation failed',
            error: e.class.name,
            Labkit::Fields::GL_USER_ID => user.id
          )
          nil
        end

        def decode_token(token, expected_sub_prefix: 'user:')
          decode_opts = {
            algorithm: ALGORITHM,
            verify_iss: true,
            iss: ISSUER,
            verify_aud: true,
            aud: AUDIENCE
          }
          decode_opts[:required_claims] = ['exp'] unless skip_expiration?

          decoded = JWT.decode(token, secret, true, decode_opts)

          sub = decoded&.first&.dig('sub')
          return unless sub&.start_with?(expected_sub_prefix)

          decoded
        rescue Errno::ENOENT => e
          logger.warn(
            message: 'Knowledge Graph secret file not configured',
            secret_path: secret_path,
            error: e.class.name
          )
          nil
        rescue JWT::DecodeError, JWT::ExpiredSignature, JWT::VerificationError => e
          logger.warn(message: 'Knowledge Graph JWT decode failed', error: e.class.name)
          nil
        end

        def authorization_header(user:, request_context:)
          token = generate_token(user: user, request_context: request_context)
          return unless token

          "Bearer #{token}"
        end

        def instance_identity
          {
            instance_id: Gitlab::GlobalAnonymousId.instance_id,
            unique_instance_id: unique_instance_id,
            host_name: Gitlab.config.gitlab.host,
            instance_version: Gitlab.version_info.to_s
          }
        end

        private

        def build_payload(context:, current_time:, request_context:)
          user = context.user

          payload = {
            sub: "user:#{user.id}",
            iat: current_time,
            iss: ISSUER,
            aud: AUDIENCE,
            user_id: user.id,
            username: user.username,
            admin: context.admin_user?,
            organization_id: user.organization_id,
            min_access_level: Gitlab::Access::REPORTER,
            **instance_identity,
            global_user_id: Gitlab::GlobalAnonymousId.user_id(user),
            deployment_type: ::CloudConnector.deployment_type,
            realm: ::CloudConnector.gitlab_realm,
            is_gitlab_team_member: ::Gitlab::Com.gitlab_com_group_member?(user),
            user_type: user.user_type,
            root_namespace_id: user.user_preference.knowledge_graph_governing_namespace_with_fallback&.id
          }

          payload.merge!(request_context.to_h.slice(:source_type, :session_id, :request_id, :token_type).compact)
          payload.merge!(license_checksum_claim)

          payload[:exp] = current_time + TOKEN_EXPIRE_TIME.to_i unless skip_expiration?

          payload.merge!(context.reporter_plus_traversal_ids) unless context.admin_user?

          payload
        end

        def unique_instance_id
          return Gitlab::GlobalAnonymousId.instance_uuid if ::CloudConnector.gitlab_realm_saas?

          ::CloudConnector::Tokens.cloud_connector_instance_uid || Gitlab::GlobalAnonymousId.instance_uuid
        end

        def license_checksum_claim
          return {} unless ::CloudConnector.gitlab_realm == ::CloudConnector::GITLAB_REALM_SELF_MANAGED

          license = ::License.current
          return {} unless license&.online_cloud_license?

          { license_checksum: license.checksum }
        end

        def skip_expiration?
          return false unless Rails.env.development? || Rails.env.test?

          Gitlab::Utils.to_boolean(ENV['KNOWLEDGE_GRAPH_JWT_SKIP_EXPIRY'])
        end

        def logger
          @logger ||= ::Gitlab::KnowledgeGraph::Logger.build
        end
      end
    end
  end
end

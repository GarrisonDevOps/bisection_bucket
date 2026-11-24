# frozen_string_literal: true

module Authn
  module Tokens
    # Verifies short-lived, stateless (no DB row) RS256 JWTs issued by
    # TokenIssuer for the `gitlab-rails` audience, duck-typed as an OAuth
    # access token. Not tied to any caller; Duo Workflow is currently the only issuer.
    class StatelessAccessToken
      include Gitlab::Utils::StrongMemoize
      include Authn::Tokens::Concerns::DoorkeeperCompatible

      # Distinguishes this from other TokenIssuer consumers (e.g. Artifact
      # Registry) and other routable token types, per
      # https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/cells/routable_tokens/.
      TOKEN_PREFIX = 'glsat-'

      # Not shared with other TokenIssuer callers, so it lives here rather
      # than on TokenIssuer itself.
      RAILS_AUDIENCE = 'gitlab-rails'
      IDENTITY_KIND_USER = Authn::TokenExchange::TokenIssuer::IDENTITY_KIND_USER

      class << self
        # Issues a prefixed, routable JWT wrapped in a result duck-typing
        # OauthAccessToken. `routing` holds top-level claims, e.g. { o:, u: }.
        def issue(user:, organization:, ttl:, scopes: [], identities: [], routing: {})
          jwt = Authn::TokenExchange::TokenIssuer.new(
            audiences: RAILS_AUDIENCE,
            user: user,
            organization: organization,
            ttl: ttl,
            scopes: scopes,
            identities: identities,
            routing: { c: Gitlab.config.cell.id }.merge(routing)
          ).token

          Result.new(
            plaintext_token: "#{token_prefix}#{jwt}",
            scopes: scopes,
            expires_in: ttl,
            expires_at: Time.current + ttl
          )
        end

        def prefix?(token_string)
          !matched_prefix(token_string).nil?
        end

        # Returns a validated StatelessAccessToken, or nil if the prefix is
        # missing or the JWT fails validation (bad sig, expired, wrong
        # aud/iss, etc.). Callers are responsible for their own FF gating.
        def from_jwt(token_string)
          prefix = matched_prefix(token_string)
          return unless prefix

          jwt_string = token_string.delete_prefix(prefix)
          token = decode(jwt_string)
          return unless token&.user

          # A composite token whose identity_user can't be resolved (e.g.
          # the human account was deleted) is rejected rather than
          # silently falling back to gating on the service account.
          return if token.identities.present? && !token.identity_user

          token
        end

        private

        # A bare TOKEN_PREFIX is always accepted, even on an instance with a
        # configured prefix, so tokens issued before a prefix was set (or by
        # a differently-configured peer) still verify; matches
        # Ci::JobToken::Jwt.decode's fallback.
        def matched_prefix(token_string)
          return unless token_string.is_a?(String)

          [TOKEN_PREFIX, token_prefix].find { |prefix| token_string.start_with?(prefix) }
        end

        def token_prefix
          Authn::TokenField::PrefixHelper.prepend_instance_prefix(TOKEN_PREFIX)
        end

        # Reuses the shared verifier with GitLab's own CloudConnector key and
        # Doorkeeper's OIDC issuer/audience, not IAM's.
        def decode(jwt_string)
          result = Authn::IamService::JwtValidationService.new(
            token: jwt_string,
            jwks: -> { verification_keys },
            issuer: Doorkeeper::OpenidConnect.configuration.issuer,
            audience: RAILS_AUDIENCE,
            required_claims: %w[jti exp iat],
            verify_not_before: true
          ).execute

          return unless result.success?

          build_from_payload(result.payload[:jwt_payload])
        end

        # Memoized per-request: this is a stateless-JWT verifier called on every
        # authenticated request, so avoid a fresh Keys query each time.
        def verification_keys
          Gitlab::SafeRequestStore.fetch(:stateless_access_token_verification_keys) do
            { keys: CloudConnector::Keys.valid.map { |key| key.to_jwk.export } }
          end
        end

        def build_from_payload(payload)
          return unless payload['jti'].present? && payload['exp'].present? && payload['iat'].present?

          gitlab_claims = payload['gitlab'] || {}
          return unless gitlab_claims['token_type'] == Authn::TokenExchange::TokenIssuer::TOKEN_TYPE

          scopes = Array(gitlab_claims['scopes'])
          identities = Array(gitlab_claims['identities'])
          return unless identities.all?(Hash)

          gid = GlobalID.parse(payload['sub'].to_s)
          return unless gid&.model_name == 'User'

          user_id = gid.model_id.to_i

          new(
            user_id: user_id,
            scopes: scopes,
            id: payload['jti'],
            expires_at: Time.zone.at(payload['exp']),
            issued_at: Time.zone.at(payload['iat']),
            identities: identities
          )
        end
      end

      attr_reader :user_id, :id, :expires_at, :issued_at, :identities, :raw_scopes

      private_class_method :new

      def initialize(user_id:, scopes:, id:, expires_at:, issued_at:, identities: [])
        @user_id = user_id
        @raw_scopes = scopes
        @id = id
        @expires_at = expires_at
        @issued_at = issued_at
        @identities = identities
      end

      def revoked?
        Denylist.denied?(id)
      end

      def reload
        clear_memoization(:user)
        clear_memoization(:identity_user)
        self
      end

      # The primary subject of the token: the service account for composite
      # identity flows, or the human user for simple (non-composite) flows.
      def user
        User.find_by_id(user_id)
      end
      strong_memoize_attr :user

      # The human user embedded in the gitlab.identities claim (composite
      # identity flows only). Returns nil for simple (non-composite) tokens,
      # or if more than one kind:user entry is present (ambiguous, not yet a
      # supported shape).
      def identity_user
        user_entries = identities.select { |i| i['kind'] == IDENTITY_KIND_USER }
        return if user_entries.size != 1

        local_id = user_entries.first['local_id']
        return unless local_id

        User.find_by_id(local_id)
      end
      strong_memoize_attr :identity_user

      # Alias for compatibility with Gitlab::Auth::Identity.link_from_oauth_token.
      def scope_user
        identity_user
      end

      def to_s
        "Authn::Tokens::StatelessAccessToken(id: #{id}, user_id: #{user_id})"
      end
    end
  end
end

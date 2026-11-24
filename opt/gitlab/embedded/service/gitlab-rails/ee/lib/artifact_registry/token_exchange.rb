# frozen_string_literal: true

module ArtifactRegistry
  # Credential-acquisition seam for the client's per-user path: mints a
  # short-lived JWT for the acting user through Authn::TokenExchange::TokenIssuer,
  # in process rather than over POST /api/v4/token_exchange. Gated per
  # organization by artifact_registry_ui; see the auth design agreement:
  # https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/artifact_registry/agreements/auth/
  class TokenExchange
    include Gitlab::Utils::StrongMemoize

    # The audience AR is configured to accept in auth.token_exchange.expected_audiences.
    # Also passes DATA_ACCESS_AUDIENCE so AR can forward the token to the
    # Relationships/Lookup API.
    AR_AUDIENCE = 'gitlab-artifact-registry'

    # Mints for the organization the request addresses, not the account's home
    # one, which is the wrong answer once its groups move into promoted
    # organizations (#626558).
    def token_for(current_user, organization)
      # Keyed per user and organization, so a shared instance cannot leak one
      # user's token to another; callers build one instance per request (CachesClient).
      strong_memoize_with(:token_for, current_user, organization) do
        # A non-User principal yields nil so the client's blank-credential guard
        # fails closed. #user_request already raises on a nil current_user.
        next unless current_user.is_a?(User)

        mint_token(current_user, organization)
      end
    end

    private

    def mint_token(current_user, organization)
      # Membership is what makes the addressed organization safe to sign, the
      # same rule ArtifactRegistry::BaseService#caller_in_organization? applies.
      return unless current_user.member_of_organization?(organization)

      ::Authn::TokenExchange::TokenIssuer.new(
        audiences: [AR_AUDIENCE, ::Authn::TokenExchange::TokenIssuer::DATA_ACCESS_AUDIENCE],
        user: current_user, organization: organization
      ).token
    rescue StandardError => e
      # Deliberately broad: everything from the membership query through the
      # Cloud Connector key and the JWT/OpenSSL stack becomes ServiceUnavailable
      # rather than a 500 across the whole GraphQL request. track_exception (not
      # log-only) so a fleet-wide key failure pages on-call. The tradeoff is that
      # a bug-class error in this path also reads as an AR outage.
      ::Gitlab::ErrorTracking.track_exception(e, artifact_registry_token_mint: true, user_id: current_user.id)

      raise ::ArtifactRegistry::Client::ConfigurationError, 'Artifact Registry credential could not be minted'
    end
  end
end

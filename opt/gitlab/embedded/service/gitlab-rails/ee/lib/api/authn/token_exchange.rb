# frozen_string_literal: true

module API
  module Authn
    # PoC token-exchange endpoint for modular services. Marked experimental --
    # the surface is expected to be superseded by GATE L2 later
    # (ADR-016 / ADR-019).
    class TokenExchange < ::API::Base
      include APIGuard

      feature_category :system_access

      MAX_EXPIRES_IN_SECONDS = ::Authn::TokenExchange::Audience.all.map(&:max_ttl).max

      # RFC 8693 token type URI for the JWT this endpoint issues.
      ISSUED_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt'

      before do
        authenticate!
      end

      namespace 'token_exchange' do
        desc 'Issue a short-lived JWT for a single modular-service audience' do
          detail 'Issues a short-lived RS256 JWT scoped to one modular-service audience ' \
            '(such as the Artifact Registry). Claims include the requesting user id (sub), ' \
            'organization id, and deployment realm (saas / self-managed). When called with a ' \
            'CI/CD ID token, the claims also carry its build metadata. Presented to the ' \
            'corresponding backend and verified against the instance JWKS. The response uses ' \
            'the RFC 8693 names. token and access_token have the same value, with ' \
            'access_token preferred where possible.'
          success code: 201, model: ::API::Entities::Authn::TokenExchange
          failure [
            { code: 400, message: 'Bad Request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 409, message: 'Conflict' }
          ]
          tags %w[token_exchange]
        end
        route_setting :lifecycle, :experiment
        # Internal-only endpoint -- not exposed via the granular PAT system.
        # All existing PATs (legacy or granular) can call this endpoint without
        # needing to opt into a per-endpoint permission.
        # skip_job_token_policies: this endpoint does not act on a project
        # resource (no read_*/admin_* policy from ci_job_token_policies.json fits).
        # The job token is only the auth credential; the token we mint is
        # scoped via `audience`.
        route_setting :authorization,
          skip_granular_token_authorization: :modular_service_token_exchange,
          skip_job_token_policies: true
        # AR auth interface agreement R1: must accept CI job tokens.
        # The endpoint is not project-scoped, so any job token authenticates as
        # the user who runs the job (current_user becomes job.user).
        #
        # Deploy tokens are deliberately NOT enabled here: DeployToken is not a
        # User, so our User-shaped payload (sub, gitlab_organization_id) doesn't
        # apply. R1 lists deploy tokens but R3 ("the principal's GitLab ID") has
        # no defined shape for non-User callers. Tracked as a follow-up.
        #
        # ADR-020 R1: a CI/CD ID token whose `aud` is this endpoint's URL. AutoFlow
        # refuses it like any CI caller (see #authorize_audience!).
        route_setting :authentication, job_token_allowed: true, ci_id_token_allowed: true
        params do
          requires :audience, type: String,
            values: ::Authn::TokenExchange::Audience.names,
            desc: 'Target service audience.'
          optional :expires_in, type: Integer,
            values: 1..MAX_EXPIRES_IN_SECONDS,
            default: ::Authn::TokenExchange::TokenIssuer::DEFAULT_TTL_SECONDS,
            desc: 'Requested token lifetime in seconds. ' \
              'The granted lifetime may be shorter than requested depending on the ' \
              'authentication method used to call this endpoint or the audience.'
          optional :organization_id, type: Integer,
            desc: 'ID of the organization to mint the token for. ' \
              'Required for Artifact Registry when the caller belongs to more than one.'
        end
        helpers do
          # Counts callers in several Artifact Registry organizations that did
          # not pass organization_id. Expected to drop to zero once glab sends it.
          def ambiguous_organization_counter
            ::Gitlab::Metrics.counter(
              :token_exchange_ambiguous_organization_total,
              'Token exchange requests refused because the audience could not pick one ' \
                'organization for the caller'
            )
          end

          # An audience that is off for this caller, or closed to job tokens, answers
          # as an unknown one, so a caller cannot tell it exists.
          def authorize_audience!(audience)
            return if audience.enabled?(current_user) && (audience.job_token_allowed? || !ci_caller?)

            error!('audience does not have a valid value', 400)
          end

          # A CI/CD ID token is issued to a job, so it counts as a CI caller too.
          def ci_caller?
            current_authenticated_job.present? || current_ci_id_token.present?
          end

          # A job token must not mint a credential that outlives its job. Past
          # the deadline the runner has already killed the script, so refuse
          # rather than grant a window the caller could keep renewing.
          def job_token_ttl_ceiling!(job)
            deadline = job.started_at && job.timeout_value && (job.started_at + job.timeout_value.seconds)
            # Deadline unknown: the default, not the endpoint cap.
            return ::Authn::TokenExchange::TokenIssuer::DEFAULT_TTL_SECONDS unless deadline

            remaining = (deadline - Time.current).to_i
            forbidden!(_('The job that requested this token has exceeded its timeout.')) unless remaining > 0

            remaining
          end

          def id_token_ttl_ceiling!(id_token)
            remaining = (id_token.expires_at - Time.current).to_i
            # The same status the finder returns for an expired ID token.
            unauthorized!('The CI/CD ID token that requested this token has expired.') unless remaining > 0

            remaining
          end

          def credential_type
            return 'ci_job_token' if current_authenticated_job
            return 'ci_id_token' if current_ci_id_token

            token = access_token
            return 'stateless_access_token' if token.is_a?(::Authn::Tokens::StatelessAccessToken)
            return 'oauth' if token.is_a?(::OauthAccessToken) || token.is_a?(::Authn::Tokens::IamOauthToken)
            return 'other' unless token.is_a?(::PersonalAccessToken)
            return 'resource_access_token' if token.user.project_bot?
            return 'service_account_pat' if token.user.service_account?

            token.granular? ? 'granular_pat' : 'pat'
          end
        end

        post do
          id_token = current_ci_id_token
          audience = ::Authn::TokenExchange::Audience.find(declared_params[:audience])
          authorize_audience!(audience)

          check_rate_limit!(:token_exchange, scope: { user: current_user })

          ttl = [declared_params[:expires_in], audience.max_ttl].min
          ttl = [ttl, job_token_ttl_ceiling!(current_authenticated_job)].min if current_authenticated_job
          ttl = [ttl, id_token_ttl_ceiling!(id_token)].min if id_token

          # Never the X-GitLab-Organization-ID header: nothing verifies it.
          organization =
            begin
              ::Authn::TokenExchange::OrganizationResolver.new(
                current_user, audience: audience.name, organization_id: declared_params[:organization_id]
              ).execute
            rescue ::Authn::TokenExchange::OrganizationResolver::AmbiguousOrganizationError => e
              ambiguous_organization_counter.increment(audience: audience.name)
              conflict!(e.message)
            rescue ::Authn::TokenExchange::OrganizationResolver::OrganizationNotFoundError
              not_found!('Organization')
            end

          # A job token only mints for its own project's organization, named or
          # inferred, so editing a pipeline can't reach another organization the
          # job's user belongs to. The no-Artifact-Registry fallback reaches nothing.
          if current_authenticated_job &&
              organization.id != current_authenticated_job.project.organization_id &&
              organization.artifact_registry_activated?
            not_found!('Organization')
          end

          token = ::Authn::TokenExchange::TokenIssuer.new(
            audiences: audience.audiences,
            user: current_user,
            organization: organization,
            ttl: ttl,
            job_claims: id_token&.job_claims
          ).token

          track_event(
            'issue_token_exchange_token',
            user: current_user,
            additional_properties: { label: declared_params[:audience], property: credential_type }
          )

          present(
            {
              access_token: token,
              issued_token_type: ISSUED_TOKEN_TYPE,
              token_type: 'Bearer',
              expires_in: ttl,
              # Same value as access_token. Artifact Registry clients read it today, and Docker's token auth
              # flow expects it too: https://gitlab.com/gitlab-org/gitlab/-/issues/604870
              token: token
            },
            with: ::API::Entities::Authn::TokenExchange
          )
        end
      end
    end
  end
end

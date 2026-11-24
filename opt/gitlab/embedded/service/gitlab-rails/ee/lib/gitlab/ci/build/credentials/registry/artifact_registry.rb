# frozen_string_literal: true

module Gitlab
  module Ci
    module Build
      module Credentials
        module Registry
          # A registry credential for the Artifact Registry host, carrying a token issued for the
          # job's user, so the runner pulls Artifact Registry images in `image:` and `services:`
          # before the job script runs. See S16:
          # https://gitlab.com/gitlab-org/ops/artifact-registry/-/blob/main/docs/specs/monolith/S16-ci-job-image-pull-credentials.md
          class ArtifactRegistry < Credentials::Base
            include ::Gitlab::Utils::StrongMemoize

            # The ADR-020 maximum, the same cap as API::Authn::TokenExchange::MAX_EXPIRES_IN_SECONDS.
            MAX_TTL_SECONDS = 12.hours.to_i

            # The Kubernetes executor writes payload credentials into a Secret in the build
            # namespace, which other workloads there can read.
            KUBERNETES_EXECUTOR = 'kubernetes'
            UNKNOWN_EXECUTOR = 'unknown'

            def self.counter
              ::Gitlab::Metrics.counter(
                :gitlab_ci_artifact_registry_pull_credentials_total,
                'Artifact Registry registry credentials issued or skipped for CI job payloads'
              )
            end

            def initialize(build)
              @build = build
            end

            def type
              'registry'
            end

            def url
              ::Gitlab::Utils.parse_url(::ArtifactRegistry::Configuration.client_base_url)&.authority
            end

            def username
              ::Gitlab::Auth::CI_JOB_USER
            end

            def password
              token
            end

            # Issues the token here, so an issuer error stays inside the credential: the factory keeps
            # only valid credentials, and an error raised while the payload is built drops the job.
            def valid?
              token.present?
            end

            private

            attr_reader :build

            delegate :project, :user, to: :build, private: true

            def token
              reason = skip_reason

              if reason
                count(:skipped, reason)
                return
              end

              issue_token.tap { count(:issued) }
            rescue ::Ci::RegisterJobService::PhaseTimeoutError
              # The job request's own time budget: dropping the job with `scheduler_failure` is
              # the request's decision, not an error of this credential.
              raise
            rescue StandardError => e
              # A database check or the issuer failing must not drop a job that may not even
              # use an Artifact Registry image. Logged, not sent: Sentry sends in the calling
              # thread inside the phase timer, and its rescue would swallow the phase timeout.
              ::Gitlab::ErrorTracking.log_exception(
                e, { Labkit::Fields::GL_PROJECT_ID => project.id, job_id: build.id }
              )
              count(:skipped, :error)
              nil
            end
            strong_memoize_attr :token

            # The conditions held in memory first, then the two that query the database, so a job
            # without the credential pays no query or signature.
            def skip_reason
              return :not_configured unless ::ArtifactRegistry::Configuration.configured?
              return :flag_disabled unless ::Feature.enabled?(:ci_artifact_registry_pull_credentials, project)
              return :kubernetes_executor if executor == KUBERNETES_EXECUTOR
              return :unknown_executor if executor.nil? || executor == UNKNOWN_EXECUTOR
              return :not_activated unless organization.artifact_registry_activated?

              :not_member unless user&.member_of_organization?(organization)
            end

            def issue_token
              ::Authn::TokenExchange::TokenIssuer.new(
                audiences: [
                  ::ArtifactRegistry::TokenExchange::AR_AUDIENCE,
                  ::Authn::TokenExchange::TokenIssuer::DATA_ACCESS_AUDIENCE
                ],
                user: user,
                organization: organization,
                ttl: ttl
              ).token
            end

            # The job's start plus its timeout, at most 12 hours. GitLab builds the payload after the
            # job is `running`, which sets its start, and every project has a build timeout.
            def ttl
              [(build.started_at + build.timeout_value.seconds - Time.current).to_i, MAX_TTL_SECONDS].min
            end

            def executor
              build.runner_manager&.executor_type
            end

            def organization
              project.organization
            end

            def count(result, reason = nil)
              self.class.counter.increment(result: result.to_s, reason: reason.to_s)
            end
          end
        end
      end
    end
  end
end

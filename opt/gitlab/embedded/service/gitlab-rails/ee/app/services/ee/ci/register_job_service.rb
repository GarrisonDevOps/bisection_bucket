# frozen_string_literal: true

module EE
  module Ci
    module RegisterJobService
      extend ::Gitlab::Utils::Override

      # Applied to each HTTP phase (open/read/write) of each CustomersDot
      # request, not to the whole resolution: resolution issues two sequential
      # requests, so worst-case scheduling delay is a small multiple of this.
      # Covers a normal cold resolve plus jitter; the gate fails open past this.
      SECRETS_MANAGER_ENTITLEMENT_TIMEOUT_SECONDS = 1.0

      # Caps job pickup at ~one CustomersDot resolution per namespace per TTL.
      # Shared with EE::Ci::BuildRunnerPresenter (see SecretsManagement::Entitlement::JOB_PICKUP_CACHE_TTL).
      SECRETS_MANAGER_ENTITLEMENT_CACHE_TTL = ::SecretsManagement::Entitlement::JOB_PICKUP_CACHE_TTL

      override :pre_assign_runner_checks
      def pre_assign_runner_checks
        super.merge({
          ip_restriction_failure: ->(build, _) { build.project.group && !::Gitlab::IpRestriction::Enforcer.new(build.project.group).allows_current_ip? },
          secrets_provider_not_found: ->(build, _) { secrets_provider_not_found?(build) },
          secrets_manager_access_denied: ->(build, _) { secrets_manager_access_denied?(build) },
          duo_workflow_not_allowed: ->(build, _) { duo_workflow_not_allowed?(build) }
        })
      end

      private

      # A gate timeout here fails open (see below), so the build reaches
      # EE::Ci::BuildRunnerPresenter, which raises this same error class if the
      # entitlement it re-resolves there denies. Map it to the accurate reason
      # instead of the generic scheduler_failure the CE rescue would otherwise use.
      override :known_exception_failure_reason
      def known_exception_failure_reason(exception)
        return :secrets_manager_access_denied if exception.is_a?(::SecretsManagement::Entitlement::AccessDeniedError)
        return :secrets_manager_source_not_accessible if exception.is_a?(::SecretsManagement::SourceNotAccessibleError)

        super
      end

      def duo_workflow_not_allowed?(build)
        build.pipeline.duo_workflow? && !Ai::DuoWorkflow::RunnerValidator.new(runner, build.project, build: build).valid?
      end

      def secrets_provider_not_found?(build)
        return false unless build.ci_secrets_management_available?
        return false unless build.secrets?

        !build.secrets_provider?(build.secrets)
      end

      # Mirrors the entitlement gate in EE::Ci::BuildRunnerPresenter, but drops
      # the build before runner assignment so users see a dedicated failure
      # reason instead of an opaque runner secret-resolution error.
      def secrets_manager_access_denied?(build)
        return false unless build.secrets?
        return false unless requests_gitlab_secrets_manager_secrets?(build)
        return false unless secrets_manager_licensed?(build.project)

        root_ancestor = build.project.root_ancestor

        # The entitlement alone can't tell that the runner payload would strip the
        # secrets: an opted-out group (GitLab.com) or an unenrolled instance
        # (Self-Managed) keeps it. Only the availability check knows, so drop the
        # job here with a clear reason instead of failing it mid-run. Projects in
        # personal namespaces can't use Secrets Manager, so only groups are checked.
        return true if root_ancestor.is_a?(::Group) && !::SecretsManagement::Availability.for_group?(root_ancestor)

        entitlement_namespace = ::SecretsManagement::Entitlement.root_namespace_for(root_ancestor)
        entitlement = secrets_manager_entitlement(entitlement_namespace)
        return false if entitlement.nil? || entitlement.permits_direct_read?

        ::SecretsManagement::Entitlement::DenialTelemetry.track(
          entitlement: entitlement,
          surface: :job_scheduling,
          namespace: entitlement_namespace
        )

        true
      end

      def requests_gitlab_secrets_manager_secrets?(build)
        build.secrets.any? { |_, config| config.key?('gitlab_secrets_manager') }
      end

      def secrets_manager_licensed?(project)
        project.licensed_feature_available?(::SecretsManagement::Availability::LICENSED_FEATURE)
      end

      # Fail-open: on resolution failure the build is scheduled as before.
      # Nothing caches the failure, so the runner presenter re-resolves the
      # entitlement (with default HTTP timeouts) when building the payload.
      #
      # Log-only, not track_exception: Sentry sends in the calling thread
      # (background_worker_threads = 0) and this runs inside the pre-assign phase
      # budget. The presenter's non-bang `Entitlement.for` reports it instead,
      # once, later in the same request.
      def secrets_manager_entitlement(namespace)
        ::SecretsManagement::Entitlement.for!(
          namespace,
          http_timeout: SECRETS_MANAGER_ENTITLEMENT_TIMEOUT_SECONDS,
          cache_ttl: SECRETS_MANAGER_ENTITLEMENT_CACHE_TTL
        )
      rescue StandardError => e
        ::Gitlab::ErrorTracking.log_exception(e, ::Labkit::Fields::GL_NAMESPACE_ID => namespace&.id)
        nil
      end
    end
  end
end

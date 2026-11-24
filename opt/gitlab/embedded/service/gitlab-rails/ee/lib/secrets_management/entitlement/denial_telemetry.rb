# frozen_string_literal: true

module SecretsManagement
  class Entitlement
    # Emits structured telemetry (an internal event plus a structured log
    # line) whenever Secrets Manager access is denied by entitlement state.
    # One firing point shared by every denial entry point: the GraphQL write
    # concern, the CI runner payload gate, the job-scheduling drop check and
    # the service-layer entitlement gate. Policy conditions deliberately do
    # not emit: they are pure
    # predicates re-run on speculative `can?` checks and type authorization,
    # which would pollute the metric with non-actions.
    #
    # `mode` is always `enforce`: observe mode (would-deny telemetry without
    # enforcement) was deliberately skipped; the property is kept so
    # dashboards need no schema change if it lands later.
    class DenialTelemetry
      extend ::Gitlab::InternalEventsTracking

      EVENT_NAME = 'secrets_manager_access_denied'
      MODE = 'enforce'
      SURFACES = %i[graphql_mutation ci_runner_payload service_gate job_scheduling].freeze

      class << self
        # `namespace` is the entitlement root namespace (a top-level Group,
        # or nil for instance-level entitlement on self-managed). `user` is
        # nil on surfaces with no acting user (CI runner payload).
        def track(entitlement:, surface:, namespace: nil, user: nil)
          validate_surface!(surface)

          reason = entitlement&.write_action_denial_reason
          return unless reason
          return if duplicate_in_request?(namespace, reason)

          track_internal_event(
            EVENT_NAME,
            namespace: namespace,
            user: user,
            additional_properties: {
              label: reason.to_s,
              property: surface.to_s,
              state: entitlement.state.to_s,
              mode: MODE
            }
          )

          log_denial(namespace, entitlement, reason, surface)
        end

        private

        def validate_surface!(surface)
          return if SURFACES.include?(surface)

          raise ArgumentError, "Unknown surface: #{surface.inspect} (expected one of #{SURFACES.inspect})"
        end

        # One denied request can trip several layers (GraphQL concern, then
        # the service gate). Only the first layer emits -- it is also the
        # most specific surface, since entry points fire before services.
        # Outside a request (no SafeRequestStore) every call emits, which is
        # acceptable: those paths are bounded by their own memoization.
        def duplicate_in_request?(namespace, reason)
          return false unless ::Gitlab::SafeRequestStore.active?

          key = [:secrets_manager_denial_telemetry, namespace&.id, reason]
          return true if ::Gitlab::SafeRequestStore[key]

          ::Gitlab::SafeRequestStore[key] = true
          false
        end

        # No PII: namespace_id is the only namespace identifier (no paths,
        # no user identifiers).
        def log_denial(namespace, entitlement, reason, surface)
          ::Gitlab::AppJsonLogger.info(
            message: 'Secrets Manager access denied by entitlement',
            Labkit::Fields::GL_NAMESPACE_ID => namespace&.id,
            denial_reason: reason.to_s,
            entitlement_state: entitlement.state.to_s,
            surface: surface.to_s,
            mode: MODE
          )
        end
      end
    end
  end
end

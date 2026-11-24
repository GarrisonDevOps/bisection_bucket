# frozen_string_literal: true

module SecretsManagement
  module EntitlementGate
    extend ActiveSupport::Concern

    private

    def validate_entitlement(action:)
      namespace = entitlement_root_namespace
      entitlement = ::SecretsManagement::Entitlement.for(namespace, user: current_user)
      return if entitlement.permits_writes?

      log_entitlement_gate_rejection(namespace, entitlement)
      ::SecretsManagement::Entitlement::DenialTelemetry.track(
        entitlement: entitlement,
        surface: :service_gate,
        namespace: namespace,
        user: current_user
      )

      ServiceResponse.error(
        message: "Secrets Manager cannot be #{action}: entitlement state is #{entitlement.state}",
        reason: :entitlement_blocked,
        payload: { state: entitlement.state, blocked_reason: entitlement.blocked_reason }
      )
    end

    def log_entitlement_gate_rejection(namespace, entitlement)
      Gitlab::AppLogger.info(
        message: 'Secrets Manager entitlement gate rejected write',
        Labkit::Fields::GL_NAMESPACE_ID => namespace&.id,
        entitlement_state: entitlement.state,
        entitlement_blocked_reason: entitlement.blocked_reason
      )
    end

    def entitlement_root_namespace
      raise NotImplementedError
    end
  end
end

# frozen_string_literal: true

module SecretsManagement
  class NamespaceEnrollmentService
    def initialize(namespace, current_user:)
      @namespace = namespace
      @current_user = current_user
    end

    def enroll
      return enrollment_not_allowed_error unless NamespaceEnrollment.enrollment_allowed?(namespace)

      existing = NamespaceEnrollment.find_by_namespace_id(namespace.id)
      return already_enrolled_response if existing&.enabled?

      # Re-enrolling clears the beta marker so a namespace that opted out
      # during the free beta does not keep free beta access.
      enrollment = existing || NamespaceEnrollment.new(namespace: namespace)
      enrollment.update!(disabled_at: nil, beta: false)

      # The beta cohort feeds the cached entitlement, same as the opt-out path.
      clear_entitlement_cache
      audit_event(name: 'secrets_manager_namespace_enroll', message: 'Enrolled namespace in Secrets Manager')

      ServiceResponse.success(payload: { enrollment: enrollment })
    rescue ActiveRecord::RecordNotUnique
      already_enrolled_response
    end

    # Opting out soft-disables the record: it marks the opt-out and stored
    # secrets are retained.
    def unenroll
      return enrollment_not_allowed_error unless NamespaceEnrollment.enrollment_allowed?(namespace)

      existing = NamespaceEnrollment.find_by_namespace_id(namespace.id)
      return already_unenrolled_response if existing && !existing.enabled?

      # Explicit false: the column defaults to true, which would wrongly claim
      # beta membership on a record that only exists to mark the opt-out.
      enrollment = existing || NamespaceEnrollment.new(namespace: namespace, beta: false)

      # Opting out pauses the add-on rather than cancelling it: the intent stays
      # so the state remains paid and re-enrolling resumes without a second
      # consent. No usage can be billed while disabled (Availability denies reads).
      enrollment.update!(disabled_at: Time.current)

      clear_entitlement_cache
      unenroll_audit_event

      ServiceResponse.success
    rescue ActiveRecord::RecordNotUnique
      already_unenrolled_response
    end

    # Add-on conversion: enrolls (when needed) and stamps the paid intent.
    # The success payload carries a rollback token capturing the pre-call
    # shape for revert_add_on_intent, so a failed enable can restore an
    # opt-out or remove a record that did not exist before the click.
    def enroll_with_add_on_intent
      existing = NamespaceEnrollment.find_by_namespace_id(namespace.id)
      rollback = existing&.slice(:disabled_at, :add_on_requested_at) || :destroy

      result = enroll

      # "Already enrolled" is the expected shape for trial-chain or beta
      # enrollees; only a forbidden answer means enrollment cannot happen.
      return result if result.error? && result.reason == :forbidden

      begin
        enrollment = NamespaceEnrollment.find_by_namespace_id(namespace.id)
        stamped = enrollment.add_on_requested_at.nil?
        enrollment.update!(add_on_requested_at: Time.current) if stamped
      rescue ActiveRecord::ActiveRecordError
        # A stamp failure raises before the rollback token reaches the caller,
        # so the enroll write must be compensated here or it leaks. Scoped to
        # persistence errors so a programming error is not masked as a rollback.
        revert_add_on_intent(rollback)
        raise
      end

      ServiceResponse.success(payload: { enrollment: enrollment, rollback: rollback, stamped: stamped })
    end

    # Restores the shape captured by enroll_with_add_on_intent: clearing only
    # the intent stamp would leave a re-enabled opt-out undone.
    def revert_add_on_intent(rollback)
      enrollment = NamespaceEnrollment.find_by_namespace_id(namespace.id)
      return ServiceResponse.success unless enrollment

      rollback == :destroy ? enrollment.destroy! : enrollment.update!(rollback)

      # enroll audited these two shapes (new row / re-enabled opt-out), so the
      # undo must audit too, or the log claims an enrollment that never stuck.
      revert_enrollment_audit_event if rollback == :destroy || rollback[:disabled_at].present?

      ServiceResponse.success
    end

    # Audited separately from enrollment: the conversion is the billing-
    # affecting action, and the trial-chain shape never re-audits enroll.
    def audit_add_on_conversion
      audit_event(name: 'secrets_manager_add_on_enable', message: 'Enabled Secrets Manager paid add-on')
    end

    private

    attr_reader :namespace, :current_user

    # The entitlement resolver reads enrollment state (add-on intent, beta
    # cohort) and CI job registration caches its answer across requests, so a
    # stale entry would keep granting secrets access for up to the TTL after
    # the opt-out.
    def clear_entitlement_cache
      ::SecretsManagement::Entitlement::Resolver.clear_cache(namespace)
    end

    def unenroll_audit_event
      audit_event(name: 'secrets_manager_namespace_unenroll', message: 'Unenrolled namespace from Secrets Manager')
    end

    def revert_enrollment_audit_event
      audit_event(
        name: 'secrets_manager_namespace_unenroll',
        message: 'Reverted Secrets Manager enrollment after failed add-on enable'
      )
    end

    def audit_event(name:, message:)
      ::Gitlab::Audit::Auditor.audit({
        name: name,
        author: current_user,
        scope: namespace,
        target: namespace,
        message: message
      })
    end

    def enrollment_not_allowed_error
      ServiceResponse.error(message: 'Namespace enrollment is not allowed.', reason: :forbidden)
    end

    def already_enrolled_response
      ServiceResponse.error(message: 'Namespace is already enrolled.')
    end

    def already_unenrolled_response
      ServiceResponse.error(message: 'Namespace is already unenrolled.')
    end
  end
end

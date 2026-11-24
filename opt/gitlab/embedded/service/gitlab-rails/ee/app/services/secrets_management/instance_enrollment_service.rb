# frozen_string_literal: true

module SecretsManagement
  class InstanceEnrollmentService
    def initialize(current_user:)
      @current_user = current_user
    end

    # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- instance enrollment is self-managed only
    def enroll
      return not_self_managed_error if ::Gitlab.com?
      return already_enrolled_response if InstanceEnrollment.enrolled?

      update_settings(secrets_manager_instance_enrolled: true, secrets_manager_instance_beta_enrolled: false)
      audit_event(name: 'secrets_manager_instance_enroll', message: 'Enrolled instance in Secrets Manager')

      ServiceResponse.success
    end

    def unenroll
      return not_self_managed_error if ::Gitlab.com?
      return not_enrolled_response unless InstanceEnrollment.enrolled?

      # Opting out pauses the add-on rather than cancelling it: the intent stays
      # so the state remains paid and re-enrolling resumes without a second
      # purchase. Nothing is billed while unenrolled (Availability denies reads).
      update_settings(secrets_manager_instance_enrolled: false)
      audit_event(name: 'secrets_manager_instance_unenroll', message: 'Unenrolled instance from Secrets Manager')

      ServiceResponse.success
    end

    # Add-on conversion: enrolls (when needed) and stamps the paid intent.
    # The rollback token records only what this call changed, never a
    # snapshot: a concurrent enable's enrollment or stamp must survive this
    # call's failure, and `stamped` is decided by the guarded write itself.
    def enroll_with_add_on_intent
      return not_self_managed_error if ::Gitlab.com?

      rollback = { enrolled: enroll.success?, stamped: false }

      begin
        rollback[:stamped] = stamp_add_on_intent
      rescue ActiveRecord::ActiveRecordError
        # A stamp failure raises before the rollback token reaches the caller,
        # so the enroll write must be compensated here or it leaks.
        revert_add_on_intent(rollback)
        raise
      end

      ServiceResponse.success(payload: { rollback: rollback, stamped: rollback[:stamped] })
    end
    # rubocop:enable Gitlab/AvoidGitlabInstanceChecks

    # Undoes only the writes recorded in the token from enroll_with_add_on_intent.
    def revert_add_on_intent(rollback)
      attributes = {}
      attributes[:secrets_manager_instance_enrolled] = false if rollback[:enrolled]
      attributes[:secrets_manager_instance_add_on_requested_at] = nil if rollback[:stamped]

      update_settings(**attributes) if attributes.any?

      # enroll audited the enrollment this flow created, so the undo must
      # audit too, or the log claims an enrollment that never stuck.
      revert_enrollment_audit_event if rollback[:enrolled]

      ServiceResponse.success
    end

    # Audited separately from enrollment: the conversion is the billing-
    # affecting action, and an already-enrolled instance never re-audits enroll.
    # Best effort: the intent is already stamped and billable, so an audit
    # write failure must not surface as a failed mutation.
    def audit_add_on_conversion
      audit_event(name: 'secrets_manager_add_on_enable', message: 'Enabled Secrets Manager paid add-on')
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e)
    end

    private

    attr_reader :current_user

    # The affected-row count of the guarded update, not an earlier read,
    # decides whether this call made the conversion.
    def stamp_add_on_intent
      stamped = InstanceEnrollment.stamp_add_on_intent!
      expire_caches

      stamped
    end

    # The guards read the row (`InstanceEnrollment.settings`), but this
    # process's cached settings may still hold the requested value; without
    # the reset, dirty tracking drops the column and the write is a no-op
    # that still reports success.
    def update_settings(**attributes)
      settings = ::Gitlab::CurrentSettings.current_application_settings
      settings.reset if settings.persisted?
      settings.update!(**attributes)
      expire_caches
    rescue StandardError => e
      ::Gitlab::ErrorTracking.track_exception(e)
      raise
    end

    # These settings feed the cached entitlement (beta window, add-on intent),
    # so the resolver cache must go too, or CI keeps the stale answer for its TTL.
    def expire_caches
      ::Gitlab::CurrentSettings.expire_current_application_settings
      InstanceEnrollment.expire_settings
      ::SecretsManagement::Entitlement::Resolver.clear_cache(nil)
    end

    def audit_event(name:, message:)
      scope = ::Gitlab::Audit::InstanceScope.new

      ::Gitlab::Audit::Auditor.audit({
        name: name,
        author: current_user,
        scope: scope,
        target: scope,
        message: message
      })
    end

    def revert_enrollment_audit_event
      audit_event(
        name: 'secrets_manager_instance_unenroll',
        message: 'Reverted Secrets Manager enrollment after failed add-on enable'
      )
    end

    def not_self_managed_error
      ServiceResponse.error(message: 'Instance enrollment is only available on self-managed instances.')
    end

    def already_enrolled_response
      ServiceResponse.error(message: 'Instance is already enrolled.')
    end

    def not_enrolled_response
      ServiceResponse.error(message: 'Instance is not enrolled.', reason: :not_found)
    end
  end
end

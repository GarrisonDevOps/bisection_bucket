# frozen_string_literal: true

module Mutations
  module SecretsManagement
    # Self-managed counterpart of `StartTrial`: admin-only, CDot is addressed by
    # `instance_id`, and the entitlement is resolved instance-wide (nil namespace).
    class InstanceStartTrial < BaseMutation
      graphql_name 'SecretsManagerInstanceStartTrial'

      include Gitlab::InternalEventsTracking

      # Same ability as the group mutation; the `:global` subject selects the
      # admin-only GlobalPolicy rule instead of GroupPolicy.
      authorize :start_secrets_manager_trial

      # The payload's EntitlementType requires read_secrets_manager, so a token
      # without it would get a silent null entitlement after a successful start.
      authorize_granular_token permissions: [:start_secrets_manager_trial, :read_secrets_manager],
        boundary: :instance,
        boundary_type: :instance,
        assignable_when: [:admin, :self_managed]

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Instance-wide Secrets Manager entitlement state after starting the trial. ' \
          'Null when the post-trial state cannot be resolved; query `secretsManagerInstanceEntitlement` instead.'

      OFFLINE_ERROR = 'Secrets Manager trials require an online cloud license.'
      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'

      ERROR_MESSAGES = {
        trial_already_active: 'A Secrets Manager trial is already active for this instance.',
        ineligible: 'This instance is not eligible to start a Secrets Manager trial.',
        not_found: 'This instance is not recognized by the subscription service.'
      }.freeze

      def resolve
        authorize!(:global)

        return failure_response(:offline) if ::SecretsManagement::InstanceEnrollment.offline_license?

        # A live resolve precedes the CDot POST so an already-trialling or
        # blocked instance is turned away without a write, and so `paid` never
        # regresses into a trial attempt.
        ineligible = eligibility_failure_reason(live_entitlement)
        return failure_response(ineligible) if ineligible

        result = ::Gitlab::SubscriptionPortal::Client.start_secrets_manager_trial(**cdot_identifier_kwargs)

        if result.success?
          after_trial_started
        else
          failure_response(failure_reason_for(result), error_message_for(result))
        end
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse::Error,
        ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e)

        failure_response(:unavailable)
      end

      private

      def after_trial_started
        # The pre-trial answers are still cached, and a blocked resolve would
        # otherwise outlive the trial for the rest of its TTL.
        expire_entitlement_caches

        # The frontend must not have to chain `instanceSecretsManagerEnroll`:
        # a trial that just started is the enrollment decision.
        enrollment_error = enroll_instance

        audit_trial_start
        track_internal_event('secrets_manager_instance_trial_started', user: current_user)

        # Trial is already started on CDot; a post-trial lookup failure must not fail the mutation.
        { entitlement: resolve_entitlement, errors: [enrollment_error].compact }
      end

      def expire_entitlement_caches
        ::Gitlab::SubscriptionPortal::Client.expire_secrets_manager_cache(**cdot_identifier_kwargs)
        ::SecretsManagement::Entitlement::Resolver.clear_cache(nil)
      end

      # Ignore every cached CDot answer: the eligibility decision has to be
      # made against the live state at click time.
      def live_entitlement
        expire_entitlement_caches

        ::SecretsManagement::Entitlement.for!(nil, user: current_user)
      end

      def eligibility_failure_reason(entitlement)
        case entitlement.state
        when :trial_eligible then nil
        when :trial then :trial_already_active
        else :ineligible
        end
      end

      # Returns the enrollment error message, or nil. Enrollment is best
      # effort: the trial has already started on CDot, so a local failure is
      # reported alongside the entitlement instead of failing the mutation.
      def enroll_instance
        return if ::SecretsManagement::InstanceEnrollment.enrolled?

        result = ::SecretsManagement::InstanceEnrollmentService.new(current_user: current_user).enroll
        return if result.success?

        result.message
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)

        'The trial started, but the instance could not be enrolled in Secrets Manager. ' \
          'Enroll it from the Admin area.'
      end

      # Best effort like enroll_instance: the trial is already started on CDot,
      # so an audit write failure must not surface as a failed mutation.
      def audit_trial_start
        scope = ::Gitlab::Audit::InstanceScope.new

        ::Gitlab::Audit::Auditor.audit({
          name: 'secrets_manager_instance_trial_start',
          author: current_user,
          scope: scope,
          target: scope,
          message: 'Started the instance-wide Secrets Manager trial'
        })
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)
      end

      def error_response(message)
        { entitlement: nil, errors: [message] }
      end

      def failure_response(reason, message = nil)
        track_internal_event(
          'secrets_manager_instance_trial_start_failed',
          user: current_user,
          additional_properties: { label: reason.to_s }
        )

        error_response(message || failure_message_for(reason))
      end

      def failure_message_for(reason)
        case reason
        when :offline then OFFLINE_ERROR
        when :unavailable then UNAVAILABLE_ERROR
        else ERROR_MESSAGES.fetch(reason)
        end
      end

      def failure_reason_for(result)
        ERROR_MESSAGES.key?(result.error_code) ? result.error_code : :unavailable
      end

      def error_message_for(result)
        return result.error_message if result.error_code == :ineligible && result.error_message.present?

        ERROR_MESSAGES.fetch(result.error_code, UNAVAILABLE_ERROR)
      end

      def resolve_entitlement
        entitlement = ::SecretsManagement::Entitlement.for!(nil, user: current_user)
        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: nil)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e)

        nil
      end

      def cdot_identifier_kwargs
        { instance_id: ::Gitlab::CurrentSettings.uuid }
      end
    end
  end
end

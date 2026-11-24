# frozen_string_literal: true

module Mutations
  module SecretsManagement
    class InstanceEnableAddOn < BaseMutation
      graphql_name 'SecretsManagerInstanceEnableAddOn'

      include Gitlab::InternalEventsTracking

      # Same ability as the group EnableAddOn mutation; the `:global` subject
      # selects the admin-only GlobalPolicy rule (self-managed, licensed)
      # instead of GroupPolicy.
      authorize :enable_secrets_manager_add_on

      # The payload's EntitlementType requires read_secrets_manager, so a token
      # without it would get a silent null entitlement after a successful enable.
      authorize_granular_token permissions: [:enable_secrets_manager_add_on, :read_secrets_manager],
        boundary: :instance,
        boundary_type: :instance,
        assignable_when: [:admin, :self_managed]

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Instance-level Secrets Manager entitlement state after enabling the add-on. ' \
          'Null when enabling failed; see errors for the reason.'

      OFFLINE_ERROR = 'The Secrets Manager add-on requires an online cloud license.'
      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'
      INELIGIBLE_ERROR = 'This instance is not eligible to enable the Secrets Manager add-on.'
      ON_DEMAND_DISABLED_ERROR = 'On-demand billing must be enabled for this instance before the Secrets ' \
        'Manager add-on can be enabled. To enable it, accept the usage billing terms in Customers Portal.'

      def resolve
        authorize!(:global)

        # An offline or legacy license converts through the activation code
        # (Resolver#resolve_offline), never through CDot.
        return failure_response(:offline) if ::SecretsManagement::InstanceEnrollment.offline_license?

        enable_add_on
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e)

        revert_add_on_intent
        failure_response(:unavailable)
      end

      private

      def enable_add_on
        entitlement = live_entitlement

        reason = eligibility_failure_reason(entitlement)
        return failure_response(reason) if reason

        enrollment_error = record_add_on_intent
        return failure_response(:enrollment_failed, enrollment_error) if enrollment_error

        confirm_conversion
      end

      # Everything after the intent is stamped runs under a revert guard: an
      # unexpected failure must not leave a stamp that silently flips the
      # instance to paid once on-demand billing turns on later.
      def confirm_conversion
        entitlement = resolve_after_intent

        unless entitlement.state == :paid
          revert_add_on_intent
          return failure_response(:not_billable)
        end

        # First conversion only: a re-click retry must not re-audit or double-count.
        if @add_on_stamped
          enrollment_service.audit_add_on_conversion
          track_internal_event('secrets_manager_add_on_enabled', user: current_user)
        end

        { entitlement: entitlement_adapter(entitlement), errors: [] }
      rescue StandardError
        revert_add_on_intent
        raise
      end

      # On-demand acceptance can be reset by a subscription renewal, so ignore
      # every cached CDot answer and validate billability at click time.
      def live_entitlement
        ::Gitlab::SubscriptionPortal::Client.expire_secrets_manager_cache(instance_id: ::Gitlab::CurrentSettings.uuid)
        ::SecretsManagement::Entitlement::Resolver.clear_cache(nil)

        ::SecretsManagement::Entitlement.for!(nil, user: current_user)
      end

      # `:paid` passes so a re-click after a partial failure is idempotent.
      def eligibility_failure_reason(entitlement)
        case entitlement.state
        when :paid then nil
        when :trial_eligible then entitlement.on_demand_enabled ? nil : :on_demand_disabled
        else :ineligible
        end
      end

      def record_add_on_intent
        result = enrollment_service.enroll_with_add_on_intent

        return result.message if result.error?

        @enrollment_rollback = result.payload[:rollback]
        @add_on_stamped = result.payload[:stamped]

        nil
      end

      def revert_add_on_intent
        return unless @enrollment_rollback

        enrollment_service.revert_add_on_intent(@enrollment_rollback)

        @enrollment_rollback = nil
      end

      def enrollment_service
        ::SecretsManagement::InstanceEnrollmentService.new(current_user: current_user)
      end

      # The CDot answers are still request-cached from the validation read;
      # only local intent changed, so drop the mapped entitlement and re-map.
      def resolve_after_intent
        ::SecretsManagement::Entitlement::Resolver.clear_cache(nil)

        ::SecretsManagement::Entitlement.for!(nil, user: current_user)
      end

      def entitlement_adapter(entitlement)
        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: nil)
      end

      def failure_response(reason, message = nil)
        track_internal_event(
          'secrets_manager_add_on_enable_failed',
          user: current_user,
          additional_properties: { label: reason.to_s }
        )

        { entitlement: nil, errors: [message || failure_message_for(reason)] }
      end

      def failure_message_for(reason)
        case reason
        when :offline then OFFLINE_ERROR
        when :on_demand_disabled then ON_DEMAND_DISABLED_ERROR
        when :unavailable then UNAVAILABLE_ERROR
        else INELIGIBLE_ERROR
        end
      end
    end
  end
end

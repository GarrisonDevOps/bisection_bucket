# frozen_string_literal: true

module Mutations
  module SecretsManagement
    class EnableAddOn < BaseMutation
      graphql_name 'SecretsManagerEnableAddOn'

      include Mutations::ResolvesGroup
      include Gitlab::InternalEventsTracking
      include ::SecretsManagement::RequiresActiveNamespace

      # Dedicated permission: enabling the paid add-on is a billing action, not
      # a plain enrollment create. GroupPolicy grants it only where
      # NamespaceEnrollment.enrollment_allowed? holds (SaaS, top-level group),
      # so no root/SaaS checks are repeated here. :provision_secrets_manager is
      # still checked explicitly once the state is paid.
      authorize :enable_secrets_manager_add_on

      # The payload's EntitlementType requires read_secrets_manager, so a token
      # without it would get a silent null entitlement after a successful enable.
      authorize_granular_token permissions: [:enable_secrets_manager_add_on, :read_secrets_manager],
        boundary_argument: :group_path,
        boundary_type: :group

      argument :group_path,
        GraphQL::Types::ID,
        required: true,
        description: 'Full path of the top-level group to enable the Secrets Manager add-on for.'

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Secrets Manager entitlement state after enabling the add-on. ' \
          'Null when enabling failed; see errors for the reason.'

      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'
      INELIGIBLE_ERROR = 'This group is not eligible to enable the Secrets Manager add-on.'
      ON_DEMAND_DISABLED_ERROR = 'On-demand billing must be enabled for this namespace before the Secrets ' \
        'Manager add-on can be enabled. To enable it, accept the usage billing terms in Customers Portal.'

      def resolve(group_path:)
        group = authorized_find!(group_path: group_path)

        raise_if_namespace_inactive!(group)

        enable_add_on(group)
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: group.id)

        revert_add_on_intent(group)
        failure_response(group, :unavailable)
      end

      private

      def enable_add_on(group)
        entitlement = live_entitlement(group)

        reason = eligibility_failure_reason(entitlement)
        return failure_response(group, reason) if reason

        enrollment_error = record_add_on_intent(group)
        return failure_response(group, :enrollment_failed, enrollment_error) if enrollment_error

        entitlement = resolve_after_intent(group)

        # The MVP has no pending intent: a click that did not convert must not
        # linger and silently flip the group to paid when on-demand turns on later.
        unless entitlement.state == :paid
          revert_add_on_intent(group)
          return failure_response(group, :not_billable)
        end

        # First conversion only: the group is billable from here regardless of
        # provisioning outcome, so both the audit event and the analytics event
        # record it now. A re-click retry must not re-audit or double-count.
        if @add_on_stamped
          enrollment_service(group).audit_add_on_conversion
          track_internal_event('secrets_manager_add_on_enabled', namespace: group, user: current_user)
        end

        provisioning_error = provision(group)
        return failure_response(group, :provisioning_failed, provisioning_error) if provisioning_error

        { entitlement: entitlement_adapter(entitlement, group), errors: [] }
      end

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end

      # On-demand acceptance can be reset by a subscription renewal, so ignore
      # every cached CDot answer and validate billability at click time.
      def live_entitlement(group)
        ::Gitlab::SubscriptionPortal::Client.expire_secrets_manager_cache(namespace_id: group.id)
        ::SecretsManagement::Entitlement::Resolver.clear_cache(group)

        ::SecretsManagement::Entitlement.for!(group, user: current_user)
      end

      # `:paid` passes so a re-click after a partial failure (intent recorded,
      # provisioning failed) can proceed straight to provisioning.
      def eligibility_failure_reason(entitlement)
        case entitlement.state
        when :paid then nil
        when :trial_eligible then entitlement.on_demand_enabled ? nil : :on_demand_disabled
        else :ineligible
        end
      end

      def record_add_on_intent(group)
        result = enrollment_service(group).enroll_with_add_on_intent

        return result.message if result.error?

        @enrollment_rollback = result.payload[:rollback]
        @add_on_stamped = result.payload[:stamped]

        nil
      end

      def revert_add_on_intent(group)
        return unless @enrollment_rollback

        enrollment_service(group).revert_add_on_intent(@enrollment_rollback)

        @enrollment_rollback = nil
        ::SecretsManagement::Entitlement::Resolver.clear_cache(group)
      end

      def enrollment_service(group)
        ::SecretsManagement::NamespaceEnrollmentService.new(group, current_user: current_user)
      end

      # The CDot answers are still request-cached from the validation read;
      # only local intent changed, so drop the mapped entitlement and re-map.
      def resolve_after_intent(group)
        ::SecretsManagement::Entitlement::Resolver.clear_cache(group)

        ::SecretsManagement::Entitlement.for!(group, user: current_user)
      end

      def provision(group)
        unless Ability.allowed?(current_user, :provision_secrets_manager, group)
          return 'You are not authorized to provision the secrets manager for this group.'
        end

        result = ::SecretsManagement::GroupSecretsManagers::InitializeService
          .new(group, current_user)
          .execute

        return if result.success?
        # Benign: a re-click after a partial failure proceeds past provisioning.
        return if result.reason == :already_initialized

        result.message
      end

      def entitlement_adapter(entitlement, group)
        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: group)
      end

      def failure_response(group, reason, message = nil)
        track_internal_event(
          'secrets_manager_add_on_enable_failed',
          namespace: group,
          user: current_user,
          additional_properties: { label: reason.to_s }
        )

        { entitlement: nil, errors: [message || failure_message_for(reason)] }
      end

      def failure_message_for(reason)
        case reason
        when :on_demand_disabled then ON_DEMAND_DISABLED_ERROR
        when :unavailable then UNAVAILABLE_ERROR
        else INELIGIBLE_ERROR
        end
      end
    end
  end
end

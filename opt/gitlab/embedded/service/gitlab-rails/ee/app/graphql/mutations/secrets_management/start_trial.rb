# frozen_string_literal: true

module Mutations
  module SecretsManagement
    class StartTrial < BaseMutation
      graphql_name 'SecretsManagerStartTrial'

      include Mutations::ResolvesGroup
      include Gitlab::InternalEventsTracking
      include ::SecretsManagement::RequiresActiveNamespace

      # Shares the enrollment gate (SaaS, top-level, licensed, namespace enrollment
      # flag): the trial flow enrolls first, so both mutations must open together.
      # Self-managed is instance-wide and admin-only: SecretsManagerInstanceStartTrial.
      authorize :start_secrets_manager_trial

      # The payload's EntitlementType requires read_secrets_manager, so a token
      # without it would get a silent null entitlement after a successful start.
      authorize_granular_token permissions: [:start_secrets_manager_trial, :read_secrets_manager],
        boundary_argument: :group_path,
        boundary_type: :group

      argument :group_path,
        GraphQL::Types::ID,
        required: true,
        description: 'Full path of the top-level group to start a Secrets Manager trial for.'

      field :entitlement,
        ::Types::SecretsManagement::EntitlementType,
        null: true,
        description: 'Secrets Manager entitlement state after starting the trial. ' \
          'Null when the post-trial state cannot be resolved; query the group entitlement directly instead.'

      UNAVAILABLE_ERROR = 'Unable to reach the subscription service. Please try again later.'
      PROVISIONING_ERROR = 'The trial started, but the secrets manager could not be enabled. ' \
        'Try again from the Secrets Manager page.'

      ERROR_MESSAGES = {
        trial_already_active: 'A Secrets Manager trial is already active for this group.',
        ineligible: 'This group is not eligible to start a Secrets Manager trial.',
        not_found: 'This group is not recognized by the subscription service.'
      }.freeze

      def resolve(group_path:)
        group = authorized_find!(group_path: group_path)

        # Before the CustomersDot call, as in EnableAddOn: the trial provisions the
        # group below, which the Initialize mutation refuses on an inactive group.
        raise_if_namespace_inactive!(group)

        ineligible = trial_ineligibility_reason(live_entitlement(group))
        return failure_response(group, ineligible, ERROR_MESSAGES.fetch(ineligible)) if ineligible

        result = ::Gitlab::SubscriptionPortal::Client.start_secrets_manager_trial(namespace_id: group.id)

        if result.success?
          # The pre-trial answers are still cached, and a blocked resolve would
          # otherwise outlive the trial for the rest of its TTL. The resolver's
          # layers go too, or the last-known-good slot lets a transport failure
          # on the lookup below replay the pre-trial answer.
          expire_entitlement_caches(group)

          track_internal_event('secrets_manager_trial_started', namespace: group, user: current_user)

          # Trial is already started on CDot; a post-trial lookup failure must not fail the mutation.
          entitlement = resolve_entitlement(group)

          # The trial is the group's enrollment, so the group is provisioned here the
          # way EnableAddOn does it after a purchase: the Owner lands on a usable page
          # and the permissions screen works at once, instead of waiting for the first
          # "New secret" click. The trial stands whatever happens below, so a
          # provisioning error is reported next to the entitlement, not instead of it.
          # The frontend chain still runs the Initialize mutation after this one;
          # it answers "already initialized", which the chain treats as benign.
          provisioning_error = provision(group)

          { entitlement: entitlement, errors: Array(provisioning_error) }
        else
          failure_response(group, failure_reason_for(result), error_message_for(result))
        end
      rescue ::Gitlab::SubscriptionPortal::SecretsManagerStartTrialResponse::Error,
        ::Gitlab::SubscriptionPortal::SecretsManagerResponseError => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: group.id)

        failure_response(group, :unavailable)
      end

      private

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end

      def error_response(message)
        { entitlement: nil, errors: [message] }
      end

      def failure_response(group, reason, message = nil)
        track_internal_event(
          'secrets_manager_trial_start_failed',
          namespace: group,
          user: current_user,
          additional_properties: { label: reason.to_s }
        )

        error_response(message || UNAVAILABLE_ERROR)
      end

      def failure_reason_for(result)
        ERROR_MESSAGES.key?(result.error_code) ? result.error_code : :unavailable
      end

      def error_message_for(result)
        return result.error_message if result.error_code == :ineligible && result.error_message.present?

        ERROR_MESSAGES.fetch(result.error_code, UNAVAILABLE_ERROR)
      end

      def expire_entitlement_caches(group)
        ::Gitlab::SubscriptionPortal::Client.expire_secrets_manager_cache(namespace_id: group.id)
        ::SecretsManagement::Entitlement::Resolver.clear_cache(group)
      end

      # Ignore every cached CDot answer: a stale `ineligible` must not turn the
      # caller away without asking CDot. `refresh!` deletes no cache first, so a
      # CDot outage here keeps the last-known-good fallback that CI reads rely on.
      def live_entitlement(group)
        ::SecretsManagement::Entitlement.refresh!(group, user: current_user)
      end

      # CDot only knows whether the namespace has trialled before; the local
      # add-on intent (paid) is invisible to it, so eligibility is checked here.
      def trial_ineligibility_reason(entitlement)
        case entitlement.state
        when :trial_eligible then nil
        when :trial then :trial_already_active
        else :ineligible
        end
      end

      def resolve_entitlement(group)
        entitlement_for(group)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: group.id)

        nil
      end

      # nil on success or when the group is already provisioned, the message
      # otherwise. Unlike EnableAddOn#provision, a denied ability is not an error:
      # the post-trial entitlement may not permit writes yet, and the group is then
      # left for the first "New secret" click.
      #
      # The trial is already started on CustomersDot, so nothing raised here may
      # replace the entitlement in the payload. InitializeService lets a failed
      # Sidekiq enqueue propagate after its records commit (the maintenance-task
      # cron retries that task), so the exception is tracked and reported as an
      # error next to the entitlement instead.
      def provision(group)
        return unless Ability.allowed?(current_user, :provision_secrets_manager, group)

        result = ::SecretsManagement::GroupSecretsManagers::InitializeService
          .new(group, current_user)
          .execute

        return if result.success?
        return if result.reason == :already_initialized

        result.message
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, gl_namespace_id: group.id)
        PROVISIONING_ERROR
      end

      # `for!` because `for` fails closed to `:ineligible` inside the resolver:
      # the rescue in `resolve_entitlement` needs the failure to propagate, and
      # the field is documented as null when the state cannot be resolved.
      def entitlement_for(group)
        entitlement = ::SecretsManagement::Entitlement.for!(group, user: current_user)
        ::Types::SecretsManagement::EntitlementType::Adapter.new(entitlement: entitlement, group: group)
      end
    end
  end
end

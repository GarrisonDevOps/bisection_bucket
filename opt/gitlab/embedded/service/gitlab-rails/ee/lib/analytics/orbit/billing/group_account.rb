# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      class GroupAccount
        include ::Gitlab::Utils::StrongMemoize
        include Account

        TRIAL_START_EVENTS = { started: 'orbit_trial_started', failed: 'orbit_trial_start_failed' }.freeze

        def self.promo_gate_for?(root)
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
            ::Feature.enabled?(:orbit_promo_access_gate, root)
        end

        def initialize(group)
          @group = group
        end

        # A trial that Sales adds in CustomersDot has no trial row, which the promo gate needs for access.
        def record_turned_on(group)
          record_trial_enrollment if promo_gate? && trial_flow? && !promo_add_on?

          super
        end

        def end_trial_if_over
          return ServiceResponse.error(message: 'Orbit trials are not available') unless trials_in_use?
          return ServiceResponse.error(message: 'The Orbit promo add-on is active') if promo_add_on?
          return ServiceResponse.error(message: 'Trial has not ended') unless live_trial_status.trial_ended?
          return ServiceResponse.error(message: 'Orbit is already off') unless turn_off_covered_groups

          track_trial_ended
          ServiceResponse.success
        rescue ::Gitlab::SubscriptionPortal::ProductTrialResponse::UnavailableError
          raise
        rescue ::Gitlab::SubscriptionPortal::ProductTrialResponse::Error => e
          raise if e.cdot_status == 429

          ::Gitlab::ErrorTracking.track_exception(e, **error_context)
          ServiceResponse.error(message: e.message)
        end

        private

        attr_reader :group

        def record_without_trial(group)
          NamespaceEnrollment.record_beta(group.id)
        end

        def indexing_free?
          false
        end

        def licensed?(resource = nil)
          (resource || group).licensed_feature_available?(:orbit)
        end

        def promo_gate?
          self.class.promo_gate_for?(group)
        end
        strong_memoize_attr :promo_gate?

        def promo_add_on?
          promo_gate? && ::GitlabSubscriptions::AddOnPurchase.for_orbit_promo.active.by_namespace(group).exists?
        end
        strong_memoize_attr :promo_add_on?

        def trial_flow?
          ::Feature.enabled?(:orbit_trial, group)
        end
        strong_memoize_attr :trial_flow?

        # The ended-trials cron only checks groups with Orbit on, so only their trial rows are current.
        def trial_running?
          enabled_namespaces = ::Analytics::KnowledgeGraph::EnabledNamespace.for_root_namespace_id(group.id)
          NamespaceEnrollment.trials_not_ended_for(enabled_namespaces).exists?
        end

        # Under the promo gate a trial row gives access, so it must end also when orbit_trial is off.
        def trials_in_use?
          trial_flow? || promo_gate?
        end

        def trial_status
          Trial.request_status_for(group)
        end
        strong_memoize_attr :trial_status

        def live_trial_status
          Trial.status_for(group)
        end

        def bills_group?(other)
          other == group
        end

        def trial_covers_group?(other)
          bills_group?(other)
        end

        def trial_policy_subject
          group
        end

        def trial_visible_to?(user, other)
          ::Ability.allowed?(user, :read_orbit_trial, other)
        end

        def trial_offer_visible_to?(user, other)
          ::Ability.allowed?(user, :start_orbit_trial, other)
        end

        def missing_license_reason
          :free_plan
        end

        def cdot_identity
          { namespace_id: group.id }
        end

        def trial_start_blocker
          indexable = ::Analytics::KnowledgeGraph::EnabledNamespace.new(root_namespace_id: group.id)
          indexable.errors.full_messages.to_sentence unless indexable.valid?
        end

        def record_trial_requested
          NamespaceEnrollment.record_trial(group.id)
        end

        def after_trial_started(user, **)
          record_trial_enrollment

          result = ::Analytics::KnowledgeGraph::ToggleNamespaceService
            .new(group: group, current_user: user, enabled: true).execute
          return result if result.error?

          ServiceResponse.success(payload: { group: group })
        end

        def record_trial_enrollment
          NamespaceEnrollment.convert_beta_to_trial(group.id)
          # The beta cleanup can delete the beta row before the conversion above, which would leave no row.
          NamespaceEnrollment.record_trial(group.id)
        end

        # trial_ended_at is when GitLab turned Orbit off, which can be later than the trial end in CDot.
        def turn_off_covered_groups
          ApplicationRecord.transaction do
            deleted_count = ::Analytics::KnowledgeGraph::EnabledNamespace.for_root_namespace_id(group.id).delete_all
            next false if deleted_count == 0

            group.orbit_namespace_enrollment&.update!(trial_ended_at: Time.current)
            true
          end
        end

        def track_trial_ended
          track_internal_event('orbit_trial_ended', namespace: group)
        end

        def event_context
          { namespace: group }
        end

        def error_context
          { gl_namespace_id: group.id }
        end

        def trial_ended_message
          s_(
            'Orbit|The GitLab Orbit trial for this group has ended. Add GitLab Credits to turn it on again.'
          )
        end

        def trial_required_message
          s_('Orbit|Start a trial to turn on GitLab Orbit for this group.')
        end

        def purchase_required_message
          s_('Orbit|Contact sales to get GitLab Orbit for this group.')
        end

        def trial_start_message(reason)
          {
            forbidden: s_('Orbit|You do not have permission to start a GitLab Orbit trial for this group.'),
            cannot_be_indexed: s_('Orbit|GitLab Orbit could not turn on for this group. Try again.'),
            ineligible: s_('Orbit|Contact sales to get GitLab Orbit for this group.'),
            trial_ended: s_(
              'Orbit|The GitLab Orbit trial has ended. Contact sales to keep using GitLab Orbit.'
            ),
            unavailable: s_('Orbit|GitLab Orbit is not available right now. Try again later.')
          }.fetch(reason)
        end
      end
    end
  end
end

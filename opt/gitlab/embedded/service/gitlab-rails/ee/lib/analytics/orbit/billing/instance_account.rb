# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      class InstanceAccount
        include ::Gitlab::Utils::StrongMemoize
        include Account

        TRIAL_START_EVENTS = {
          started: 'orbit_instance_trial_started', failed: 'orbit_instance_trial_start_failed'
        }.freeze

        # Skipped under the trial flow or the promo gate, which don't track access with an enrollment row.
        def record_auto_indexed(group_ids)
          NamespaceEnrollment.record_direct(group_ids) unless trial_flow? || promo_gate?
        end

        private

        def record_without_trial(group)
          NamespaceEnrollment.record_direct(group.id)
        end

        def indexing_free?
          true
        end

        def licensed?(_resource = nil)
          ::License.feature_available?(:orbit)
        end

        def promo_gate?
          ::Feature.enabled?(:orbit_promo_access_gate, :instance)
        end
        strong_memoize_attr :promo_gate?

        def promo_add_on?
          promo_gate? && ::GitlabSubscriptions::AddOnPurchase.for_active_add_ons(:orbit_promo, :instance).exists?
        end
        strong_memoize_attr :promo_add_on?

        # CDot recognizes an instance through its online cloud license.
        def trial_flow?
          ::Feature.enabled?(:orbit_trial, :instance) && !!::License.current&.online_cloud_license?
        end
        strong_memoize_attr :trial_flow?

        def trial_running?
          trial_flow? && trial_status != :unavailable && trial_status.trial_active?
        end

        def trial_status
          Trial.request_instance_status
        end
        strong_memoize_attr :trial_status

        def live_trial_status
          Trial.status_for_instance
        end

        def bills_group?(_group)
          false
        end

        def trial_covers_group?(_group)
          true
        end

        def trial_policy_subject
          :global
        end

        def trial_visible_to?(_user, _group)
          trial_offered?
        end

        # An administrator starts the instance trial, so an Owner sees it as eligible, not as licensed.
        def trial_offer_visible_to?(_user, _group)
          true
        end

        def missing_license_reason
          :no_license
        end

        def cdot_identity
          { instance_id: ::Gitlab::CurrentSettings.uuid }
        end

        def trial_start_blocker; end

        def record_trial_requested; end

        def after_trial_started(user, new_trial:)
          audit_trial_start(user) if new_trial
          ServiceResponse.success
        end

        def audit_trial_start(user)
          scope = ::Gitlab::Audit::InstanceScope.new

          ::Gitlab::Audit::Auditor.audit({
            name: 'orbit_instance_trial_start',
            author: user,
            scope: scope,
            target: scope,
            message: 'Started the instance-wide Orbit trial'
          })
        rescue StandardError => e
          ::Gitlab::ErrorTracking.track_exception(e)
        end

        def event_context
          {}
        end

        def error_context
          {}
        end

        def trial_start_message(reason)
          {
            forbidden: s_('Orbit|Ask your administrator to start the trial of this instance.'),
            ineligible: s_('Orbit|Contact sales to get GitLab Orbit for this instance.'),
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

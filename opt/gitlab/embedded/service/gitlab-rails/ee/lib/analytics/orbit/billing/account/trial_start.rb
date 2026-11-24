# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      module Account
        # One trial start flow. Each account provides who may start it, how CDot identifies it, and what
        # happens after it starts.
        module TrialStart
          include ::Gitlab::InternalEventsTracking

          def start_trial(by:)
            user = by
            unless ::Ability.allowed?(user, :start_orbit_trial, trial_policy_subject)
              return trial_start_error(user, :forbidden)
            end

            blocker = trial_start_blocker
            return trial_start_error(user, :cannot_be_indexed, blocker) if blocker

            started = cdot_client.start_product_trial(trial_type: Trial::TRIAL_TYPE, **cdot_identity)
            if started.error_code.in?(%i[ineligible not_found])
              return trial_start_error(user, :ineligible,
                cdot_reason: started.error_message.presence || started.error_code.to_s)
            end

            # 201 and 409 both mean "a trial exists". Only the next read says if it is active.
            cdot_client.expire_product_trial_cache(trial_type: Trial::TRIAL_TYPE, **cdot_identity)
            clear_memoization(:trial_status)
            record_trial_requested
            return trial_start_error(user, :trial_ended) unless live_trial_status.trial_active?

            result = after_trial_started(user, new_trial: started.success?)
            return trial_start_error(user, :unavailable, result.message) if result.error?

            track_trial_event(:started, user) if started.success?
            result
          rescue ::Gitlab::SubscriptionPortal::StartProductTrialResponse::Error,
            ::Gitlab::SubscriptionPortal::ProductTrialResponse::Error => e
            ::Gitlab::ErrorTracking.track_exception(e, **error_context)
            trial_start_error(user, :unavailable)
          end

          private

          private :track_internal_event

          # CDot reasons are internal codes, so they go to the event and not to the user.
          def trial_start_error(user, reason, message = nil, cdot_reason: nil)
            unless reason == :forbidden
              track_trial_event(:failed, user,
                additional_properties: { label: reason.to_s, property: cdot_reason }.compact)
            end

            ServiceResponse.error(message: message.presence || trial_start_message(reason), reason: reason)
          end

          def track_trial_event(name, user, **properties)
            track_internal_event(self.class::TRIAL_START_EVENTS.fetch(name), user: user, **event_context, **properties)
          end

          def cdot_client
            ::Gitlab::SubscriptionPortal::Client
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      # The billing rules, written once. GroupAccount and InstanceAccount include them and keep their
      # facts private, so callers ask these questions and never branch on the facts.
      module Account
        include ::Gitlab::Utils::StrongMemoize
        include AccessRules
        include TrialStart

        TurnOn = Data.define(:denial_reason, :message) do
          def allowed?
            denial_reason.nil?
          end
        end

        UNRESOLVED = Object.new
        private_constant :UNRESOLVED

        # A project can hold its own license, for example a public project with a legacy open source license.
        def entitled?(resource = nil)
          return licensed?(resource) unless promo_gate?

          promo_add_on? || trial_running?
        end

        def access_by_plan?
          !promo_gate?
        end

        def eligible?
          licensed? || promo_add_on?
        end

        # Under the promo gate, an Owner whose access lapsed can still turn Orbit off.
        def setting_changeable?(group)
          eligible? || (promo_gate? && group.knowledge_graph_enabled_namespace.present?)
        end

        def trial_offered?
          trial_flow? && eligible? && !promo_add_on?
        end

        def trial_offered_to?(group)
          trial_offered? && trial_covers_group?(group)
        end

        # Without the promo gate, a beta group needs no trial, so a trial would use up its one CDot trial.
        def trial_startable_by?(group)
          bills_group?(group) && trial_offered? && !(beta?(group) && !promo_gate?)
        end

        def trial
          trial_status if trial_flow?
        end

        # The trial status is read only when the answer depends on it, so a group with the add-on never
        # calls CustomersDot.
        def turn_on(group, trial_status: UNRESOLVED)
          fetched = nil
          status = trial_status.equal?(UNRESOLVED) ? -> { fetched ||= live_trial_status } : -> { trial_status }

          reason = turn_on_denial_reason(group, status)

          TurnOn.new(denial_reason: reason, message: reason && turn_on_denial_message(reason))
        end

        def record_turned_on(group)
          if promo_add_on?
            NamespaceEnrollment.record_direct(group.id)
          elsif trial_flow?
            # CDot says the trial is active again, so the ended-trials cron must check this group again.
            group.orbit_namespace_enrollment&.update!(trial_ended_at: nil)
          elsif !promo_gate?
            record_without_trial(group)
          end
        end

        private

        def beta?(group)
          !!group&.orbit_namespace_enrollment&.beta?
        end

        def turn_on_denial_message(reason)
          case reason
          when :trial_ended then trial_ended_message
          when :trial_required then trial_required_message
          else purchase_required_message
          end
        end

        def turn_on_denial_reason(group, status)
          return if promo_add_on?
          return if turn_on_allowed?(group, status)
          return :trial_ended if trial_flow? && status.call&.trial_ended?
          return :purchase_required if trial_flow? && status.call&.state == :ineligible

          trial_offered? ? :trial_required : :purchase_required
        end

        def turn_on_allowed?(group, status)
          return true if indexing_free?

          if promo_gate?
            trial_flow? && !!status.call&.trial_active?
          else
            !trial_flow? || beta?(group) || !!status.call&.trial_active?
          end
        end
      end
    end
  end
end

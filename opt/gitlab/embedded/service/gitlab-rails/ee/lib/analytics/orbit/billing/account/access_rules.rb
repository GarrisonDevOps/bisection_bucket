# frozen_string_literal: true

module Analytics
  module Orbit
    module Billing
      module Account
        module AccessRules
          # Group is nil for the access of the whole account (the instance on GitLab Self-Managed).
          def access(group:, current_user:)
            user = current_user
            status = trial_status if trial_visible_to?(user, group)
            state, reason = classify_access(group, user, status)

            ::Analytics::Orbit::Access.new(
              state: state,
              reason: reason,
              turn_on_denial_reason: access_turn_on_denial_reason(group, user, status),
              trial: (status unless status == :unavailable)
            )
          end

          private

          def classify_access(group, user, status)
            return [:not_configured, nil] unless ::Analytics::KnowledgeGraph.service_configured?
            return [:unlicensed, unlicensed_reason] unless manageable_by?(user, group)
            return [:licensed, :beta] if beta?(group) && !promo_gate?
            # Before the promo gate the license runs the queries of the instance, so a trial not started offers nothing.
            return [:licensed, :plan] if group.nil? && status && !promo_gate? && !trial_started?(status)
            return classify_trial(group, user, status) if status

            # A group that lost access stays on until the hourly cron turns it off; an instance stays on.
            return [:unlicensed, :no_access] if promo_gate? && !entitled?

            [:licensed, licensed_reason(group)]
          end

          def classify_trial(group, user, status)
            return [:trial_status_unavailable, nil] if status == :unavailable
            return [:trial_active, nil] if status.trial_active?
            return [:trial_ended, trial_ended_reason(status)] if status.trial_ended?
            return [:licensed, licensed_reason(group)] unless trial_offer_visible_to?(user, group)
            return [:trial_eligible, nil] if status.state == :trial_eligible

            [:trial_not_eligible, nil]
          end

          def trial_started?(status)
            status != :unavailable && (status.trial_active? || status.trial_ended?)
          end

          # CDot zeroes the balance when a trial expires, so only the date tells an
          # expired trial apart from one that burned through its credits early.
          def trial_ended_reason(status)
            expires_at = status.trial_expires_at
            expires_at.present? && expires_at.past? ? :trial_expired : :credits_exhausted
          end

          def licensed_reason(group)
            return :promo_add_on if promo_add_on?
            return :beta if beta?(group)

            :plan
          end

          def unlicensed_reason
            promo_gate? ? :no_access : missing_license_reason
          end

          def access_turn_on_denial_reason(group, user, status)
            return unless group
            return if group.knowledge_graph_enabled_namespace.present?
            return :forbidden unless manageable_by?(user, group)
            return turn_on(group, trial_status: status).denial_reason unless status == :unavailable

            # Only a turn-on rule that needs the trial status waits for CustomersDot.
            status_read = false
            reason = turn_on_denial_reason(group, -> {
              status_read = true
              nil
            })
            status_read ? :unavailable : reason
          end

          def manageable_by?(user, group)
            return eligible? unless group

            ::Ability.allowed?(user, :update_knowledge_graph_setting, group)
          end
        end
      end
    end
  end
end

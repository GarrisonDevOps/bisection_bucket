# frozen_string_literal: true

module EE
  module Users
    module CalloutsHelper
      extend ::Gitlab::Utils::Override
      include ::Nav::GitlabDuoSettingsPage

      ACTIVE_USER_COUNT_THRESHOLD = 'active_user_count_threshold'
      NEW_USER_SIGNUPS_CAP_REACHED = 'new_user_signups_cap_reached'
      PERSONAL_ACCESS_TOKEN_EXPIRY = 'personal_access_token_expiry'
      PROFILE_PERSONAL_ACCESS_TOKEN_EXPIRY = 'profile_personal_access_token_expiry'
      JOINING_A_PROJECT_ALERT = 'joining_a_project_alert'
      PIPL_COMPLIANCE_ALERT = 'pipl_compliance_alert'
      DUO_CORE_RELEASE_DATE = Date.new(2025, 5, 15)

      override :render_dashboard_ultimate_trial
      def render_dashboard_ultimate_trial(user)
        return unless user
        return unless ::Gitlab::Saas.feature_available?(:subscriptions_trials)
        return unless user_default_dashboard?(user)
        return unless !user.owns_paid_namespace? && user.owns_group_without_trial?

        render 'shared/ultimate_with_enterprise_trial_callout_content'
      end

      def show_pipl_compliance_alert?
        ::Gitlab::Saas.feature_available?(:pipl_compliance) &&
          !user_dismissed?(PIPL_COMPLIANCE_ALERT) &&
          ::ComplianceManagement::Pipl.user_subject_to_pipl?(current_user) &&
          ::Gitlab::CurrentSettings.enforce_pipl_compliance? &&
          current_user.pipl_user.initial_email_sent_at.present?
      end

      def show_compromised_password_detection_alert?
        return false unless ::Gitlab::Saas.feature_available?(:notify_compromised_passwords)

        current_user&.compromised_password_detections&.unresolved&.exists?
      end

      def show_new_user_signups_cap_reached?
        return false unless current_user&.can_admin_all_resources?
        return false if user_dismissed?(NEW_USER_SIGNUPS_CAP_REACHED)
        return false unless ::Gitlab::CurrentSettings.seat_control_user_cap?

        new_user_signups_cap = ::Gitlab::CurrentSettings.new_user_signups_cap

        new_user_signups_cap.to_i <= ::User.billable.count
      end

      def show_joining_a_project_alert?
        return false unless cookies[:signup_with_joining_a_project]
        return false unless ::Gitlab::Saas.feature_available?(:onboarding)

        !user_dismissed?(JOINING_A_PROJECT_ALERT)
      end

      override :show_transition_to_jihu_callout?
      def show_transition_to_jihu_callout?
        !gitlab_com_subscription? && !has_active_license? && super
      end

      private

      override :dismissed_callout?
      def dismissed_callout?(object, query)
        return super if object.is_a?(Project)

        current_user.dismissed_callout_for_group?(group: object, **query)
      end
    end
  end
end

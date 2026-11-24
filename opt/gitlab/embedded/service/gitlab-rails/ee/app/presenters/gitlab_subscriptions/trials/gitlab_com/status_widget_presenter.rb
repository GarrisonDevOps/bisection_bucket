# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module GitlabCom
      class StatusWidgetPresenter < Gitlab::View::Presenter::Simple
        include Gitlab::Utils::StrongMemoize

        presents ::Namespace, as: :namespace

        EXPIRED_TRIAL_WIDGET = 'expired_trial_status_widget'
        # Matches the post-trial billing page card window so both surfaces disappear together.
        TIME_FRAME_AFTER_EXPIRATION = 45.days
        private_constant :TIME_FRAME_AFTER_EXPIRATION

        def attributes
          return {} unless eligible_for_widget?

          {
            trial_widget_data_attrs: {
              trial_type: 'ultimate_with_dap',
              trial_days_used: trial_status.days_used,
              days_remaining: trial_status.days_remaining,
              percentage_complete: trial_status.percentage_complete,
              group_id: namespace.id,
              trial_discover_page_path: group_discover_path(namespace),
              purchase_now_url: group_billings_path(namespace),
              feature_id: EXPIRED_TRIAL_WIDGET
            }
          }
        end

        private

        def eligible_for_widget?
          eligible_trial_active? || optimistic_trial_active? || eligible_expired_trial?
        end

        def eligible_trial_active?
          GitlabSubscriptions::Trials.namespace_plan_eligible_for_active?(namespace) &&
            namespace.gitlab_subscription_end_date.present? &&
            namespace.gitlab_subscription_end_date > current_date
        end

        def optimistic_trial_active?
          return false if eligible_trial_active?

          active = GitlabSubscriptions::Trials::PendingTrialMarker.active?(namespace.id)

          if active
            Gitlab::AppJsonLogger.info(
              class_name: self.class.name,
              message: 'Optimistic trial widget served from pending trial marker',
              namespace_id: namespace.id
            )
          end

          active
        end
        strong_memoize_attr :optimistic_trial_active?

        def eligible_expired_trial?
          !user_dismissed_widget? && trial_recently_expired?
        end

        def trial_recently_expired?
          # this does not cover the edge case that a premium namespace trailing ultimate becomes free around
          # the same time as trial expires, see https://gitlab.com/gitlab-org/gitlab/-/work_items/588952 for follow-up
          GitlabSubscriptions::Trials.recently_expired?(namespace, time_frame: TIME_FRAME_AFTER_EXPIRATION)
        end
        strong_memoize_attr :trial_recently_expired?

        def trial_status
          starts_on, ends_on = trial_status_dates
          GitlabSubscriptions::TrialStatus.new(starts_on, ends_on)
        end
        strong_memoize_attr :trial_status

        def trial_status_dates
          return [namespace.trial_starts_on, namespace.trial_ends_on] if trial_recently_expired?
          return [current_date, optimistic_end_date] if optimistic_trial_active?

          [namespace.gitlab_subscription_start_date, namespace.gitlab_subscription_end_date]
        end

        def current_date
          Date.current
        end
        strong_memoize_attr :current_date

        def optimistic_end_date
          # rubocop:disable CodeReuse/ServiceClass -- presenter uses the canonical trial duration service
          # to keep derived end dates in lockstep with TrialDurationService, the single source of truth
          duration_days = GitlabSubscriptions::TrialDurationService.new.execute
          # rubocop:enable CodeReuse/ServiceClass
          current_date + duration_days.days
        end

        def user_dismissed_widget?
          user.dismissed_callout_for_group?(feature_name: EXPIRED_TRIAL_WIDGET, group: namespace)
        end
      end
    end
  end
end

# Added for JiHu
# Used in https://jihulab.com/gitlab-cn/gitlab/-/blob/main-jh/jh/app/presenters/jh/gitlab_subscriptions/trials/status_widget_presenter.rb
GitlabSubscriptions::Trials::GitlabCom::StatusWidgetPresenter.prepend_mod

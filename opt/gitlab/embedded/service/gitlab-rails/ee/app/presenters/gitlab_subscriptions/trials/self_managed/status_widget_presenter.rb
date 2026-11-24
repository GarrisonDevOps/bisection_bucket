# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module SelfManaged
      class StatusWidgetPresenter < Gitlab::View::Presenter::Simple
        include Gitlab::Utils::StrongMemoize

        presents ::License, as: :license

        EXPIRED_TRIAL_WIDGET = 'expired_trial_status_widget'
        TIME_FRAME_AFTER_EXPIRATION = 45.days
        private_constant :TIME_FRAME_AFTER_EXPIRATION

        def attributes
          return {} unless eligible?

          {
            trial_widget_data_attrs: {
              trial_type: 'self_managed_ultimate',
              trial_days_used: trial_status.days_used,
              days_remaining: trial_status.days_remaining,
              percentage_complete: trial_status.percentage_complete,
              trial_discover_page_path: admin_discover_premium_path,
              purchase_now_url: promo_pricing_url(query: { deployment: 'self-managed' }),
              feature_id: EXPIRED_TRIAL_WIDGET
            }
          }
        end

        private

        def eligible?
          return false unless user
          return false unless GitlabSubscriptions::Trials.self_managed_non_dedicated_ultimate_trial?(license)

          license.active? || eligible_expired_and_not_dismissed?
        end

        def eligible_expired_and_not_dismissed?
          recently_expired? && !user_dismissed_widget?
        end

        def recently_expired?
          license.expires_at > Date.current - TIME_FRAME_AFTER_EXPIRATION
        end

        def trial_status
          GitlabSubscriptions::TrialStatus.new(license.starts_at, license.expires_at)
        end
        strong_memoize_attr :trial_status

        def user_dismissed_widget?
          user.dismissed_callout?(feature_name: EXPIRED_TRIAL_WIDGET)
        end
      end
    end
  end
end

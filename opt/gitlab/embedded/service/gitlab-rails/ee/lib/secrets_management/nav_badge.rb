# frozen_string_literal: true

module SecretsManagement
  module NavBadge
    # The badge is a temporary GA discoverability aid and stops rendering after
    # this date. Remove the badge and its callers once it lapses.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/604039
    BADGE_EXPIRES_ON = Date.new(2026, 10, 15)

    # User callout that records a user has already seen the badge. String (not
    # symbol) to match the enum's string keys in Users::Callout.feature_names
    # and User#callouts_by_feature_name.
    CALLOUT_FEATURE_NAME = 'secrets_manager_nav_badge'

    def self.visible?(user:)
      return false unless user
      return false if Date.current > BADGE_EXPIRES_ON

      !user.dismissed_callout?(feature_name: CALLOUT_FEATURE_NAME)
    end
  end
end

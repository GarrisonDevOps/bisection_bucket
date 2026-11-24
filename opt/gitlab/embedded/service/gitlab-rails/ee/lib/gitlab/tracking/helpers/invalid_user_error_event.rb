# frozen_string_literal: true

module Gitlab
  module Tracking
    module Helpers
      module InvalidUserErrorEvent
        def track_invalid_user_error(tracking_label)
          Gitlab::Tracking.event(
            'Gitlab::Tracking::Helpers::InvalidUserErrorEvent',
            "track_#{tracking_label}_error",
            label: 'failed_creating_user'
          )
        end
      end
    end
  end
end

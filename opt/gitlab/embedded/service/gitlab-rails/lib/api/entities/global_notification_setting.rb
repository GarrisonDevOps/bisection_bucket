# frozen_string_literal: true

module API
  module Entities
    class GlobalNotificationSetting < Entities::NotificationSetting
      expose :notification_email, documentation: {
        type: 'String', example: 'user@example.com', desc: 'Email address where notifications are sent.'
      } do |notification_setting, options|
        notification_setting.user.notification_email_or_default
      end
    end
  end
end

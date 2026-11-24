# frozen_string_literal: true

module API
  module Entities
    class MemberAccess < Grape::Entity
      expose :access_level, documentation: { desc: 'Access level of the current user.' }
      expose :notification_level,
        documentation: { desc: 'Notification level of the current user.' } do |member, options|
        if member.notification_setting
          ::NotificationSetting.levels[member.notification_setting.level]
        end
      end
    end
  end
end

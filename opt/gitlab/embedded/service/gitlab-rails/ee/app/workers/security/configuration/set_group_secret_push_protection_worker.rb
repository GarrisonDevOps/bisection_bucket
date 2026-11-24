# frozen_string_literal: true

module Security
  module Configuration
    class SetGroupSecretPushProtectionWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      urgency :high

      feature_category :security_testing_configuration

      def perform(group_id, enable, current_user_id = nil, excluded_projects_ids = [])
        group = Group.find_by_id(group_id)
        current_user = User.find_by_id(current_user_id)

        return unless group && current_user

        SetGroupSecretPushProtectionService.new(subject: group, enable: enable, current_user: current_user,
          excluded_projects_ids: excluded_projects_ids).execute
      end
    end
  end
end

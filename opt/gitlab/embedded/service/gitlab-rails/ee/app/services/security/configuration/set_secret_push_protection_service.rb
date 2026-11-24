# frozen_string_literal: true

module Security
  module Configuration
    class SetSecretPushProtectionService
      def self.execute(current_user:, project:, enable:)
        raise ArgumentError, 'Invalid argument. Either true or false should be passed.' unless [true,
          false].include?(enable)

        if ::Gitlab::CurrentSettings.current_application_settings.secret_push_protection_enforced && !enable
          return ServiceResponse.error(
            message: 'Secret push protection is enforced for all projects in the instance',
            payload: { enabled: nil }
          )
        end

        ServiceResponse.success(
          payload: {
            enabled: SetProjectSecretPushProtectionService.new(current_user: current_user, subject: project,
              enable: enable).execute,
            errors: []
          })

      rescue StandardError => e
        ServiceResponse.error(
          message: e.message,
          payload: { enabled: nil }
        )
      end
    end
  end
end

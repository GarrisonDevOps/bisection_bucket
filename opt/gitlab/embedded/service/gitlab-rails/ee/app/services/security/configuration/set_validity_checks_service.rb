# frozen_string_literal: true

module Security
  module Configuration
    class SetValidityChecksService
      def self.execute(current_user:, project:, enable:)
        raise ArgumentError, 'Invalid argument. Either true or false should be passed.' unless [true,
          false].include?(enable)

        ServiceResponse.success(
          payload: {
            enabled: SetProjectValidityChecksService.new(current_user: current_user, subject: project,
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

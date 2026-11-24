# frozen_string_literal: true

module SecretsManagement
  module Helpers
    module ErrorResponseHelper
      def secrets_manager_inactive_response
        ServiceResponse.error(message: 'Secrets manager is not active')
      end

      def deprovision_in_progress_response
        ServiceResponse.error(message: 'Secrets manager deprovision is in progress')
      end
    end
  end
end

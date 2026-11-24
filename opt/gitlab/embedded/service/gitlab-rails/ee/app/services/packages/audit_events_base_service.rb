# frozen_string_literal: true

module Packages
  class AuditEventsBaseService
    NOT_ELIGIBLE_ERROR = ServiceResponse.error(message: 'Not eligible for audit events').freeze

    def execute
      return NOT_ELIGIBLE_ERROR unless audit_events_enabled?

      yield

      ServiceResponse.success
    end

    private

    def audit_events_enabled?
      raise NotImplementedError
    end

    def auth_token_type
      ::Current.token_info&.dig(:token_type) || token_type_from_current_user
    end

    def token_type_from_current_user
      return unless current_user
      return 'DeployToken' if current_user.is_a?(DeployToken)
      return 'CiJobToken' if current_user.from_ci_job_token?

      'PersonalAccessToken'
    end
  end
end

# frozen_string_literal: true

module ExternalStatusChecks
  class RetryService < BaseService
    def execute
      unless Ability.allowed?(current_user, :retry_failed_status_checks, params[:merge_request])
        return unauthorized_error_response
      end

      return not_failed_error_response unless external_status_check.failed?(params[:merge_request])

      last_response = external_status_check.response_for(params[:merge_request], params[:merge_request].diff_head_sha)

      if last_response.update(retried_at: Time.current, status: 'pending')
        data = params[:merge_request].to_hook_data(current_user)
        external_status_check.async_execute(data)
        MergeRequests::StatusCheckResponses::AuditUpdateResponseService.new(last_response, current_user).execute
        GraphqlTriggers.merge_request_merge_status_updated(params[:merge_request])
        ServiceResponse.success(payload: { external_status_check: external_status_check })
      else
        ServiceResponse.error(message: 'Failed to retry external status check',
          payload: { errors: external_status_check.errors.full_messages },
          reason: :unprocessable_entity)
      end
    end

    private

    def not_failed_error_response
      ServiceResponse.error(
        message: 'Failed to retry external status check',
        payload: { errors: 'External status check must be failed' },
        reason: :unprocessable_entity
      )
    end

    def unauthorized_error_response
      ServiceResponse.error(
        message: 'Failed to retry external status check',
        payload: { errors: 'Not allowed' },
        reason: :unauthorized
      )
    end
  end
end

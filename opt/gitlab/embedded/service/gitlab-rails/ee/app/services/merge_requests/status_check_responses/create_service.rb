# frozen_string_literal: true

module MergeRequests
  module StatusCheckResponses
    class CreateService < BaseProjectService
      def execute(merge_request)
        unless Ability.allowed?(current_user, :provide_status_check_response, merge_request)
          return ServiceResponse.error(message: 'Not Found', reason: :not_found)
        end

        response = merge_request.status_check_responses.new(
          external_status_check: external_status_check,
          status: status,
          sha: sha
        )

        if response.save
          AuditUpdateResponseService.new(response, current_user).execute
          GraphqlTriggers.merge_request_merge_status_updated(merge_request)

          ServiceResponse.success(payload: { status_check_response: response })
        else
          ServiceResponse.error(
            message: 'Failed to create status check response',
            payload: { errors: response.errors.full_messages },
            reason: :bad_request
          )
        end
      end

      private

      def status
        params[:status]
      end

      def sha
        params[:sha]
      end

      def external_status_check
        params[:external_status_check]
      end
    end
  end
end

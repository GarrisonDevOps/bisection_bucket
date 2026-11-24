# frozen_string_literal: true

module Vulnerabilities
  class CreateIssueFromBulkActionService < ::BaseService
    def execute
      unless can?(@current_user, :create_issue, @project)
        return ServiceResponse.error(message: "User is not permitted to create issue")
      end

      issue_params = {
        title: title,
        confidential: true
      }

      result = ::Issues::CreateService
        .new(container: @project, current_user: @current_user, params: issue_params, perform_spam_check: false)
        .execute

      if result.success?
        ServiceResponse.success(payload: { issue: result[:issue] })
      else
        ServiceResponse.error(message: result.errors.join(', '))
      end
    end

    private

    def title
      _("Investigate vulnerabilities")
    end
  end
end

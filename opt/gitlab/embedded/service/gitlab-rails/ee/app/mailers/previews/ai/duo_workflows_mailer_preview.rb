# frozen_string_literal: true

module Ai
  class DuoWorkflowsMailerPreview < ActionMailer::Preview
    def duo_workflow_input_required_email
      workflow = ::Ai::DuoWorkflows::Workflow.last
      user = workflow&.user || User.first
      Notify.duo_workflow_input_required_email(user.id, workflow&.id)
    end
  end
end

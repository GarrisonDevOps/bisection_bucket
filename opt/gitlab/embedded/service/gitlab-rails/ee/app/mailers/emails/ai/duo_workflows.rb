# frozen_string_literal: true

module Emails
  module Ai
    module DuoWorkflows
      def duo_workflow_input_required_email(recipient_id, workflow_id)
        @workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        @recipient = User.find_by_id(recipient_id)
        return unless @workflow && @recipient

        @project = @workflow.project
        @goal = @workflow.goal.to_s.truncate(300)
        @flow = @workflow.workflow_definition
        @web_url = @workflow.web_url
        @checkpoint_message = last_request_message(@workflow)&.truncate(800)

        email_with_layout(
          to: @recipient.notification_email_for(@project&.group),
          subject: subject(s_('Notify|Your Duo session needs your input')))
      end

      private

      def last_request_message(workflow)
        workflow.latest_ui_chat_log_history.reverse.find { |m| m['message_type'] == 'request' }&.[]('content')
      end
    end
  end
end

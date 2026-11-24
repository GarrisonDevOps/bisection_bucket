# frozen_string_literal: true

module Vulnerabilities
  class FeedbackPolicy < BasePolicy
    delegate { @subject.project }

    condition(:issue, scope: :subject) { @subject.for_issue? }
    condition(:merge_request, scope: :subject) { @subject.for_merge_request? }
    condition(:dismissal, scope: :subject) { @subject.for_dismissal? }
    condition(:finding_has_vulnerability, scope: :subject) { @subject.finding&.vulnerability.present? }

    rule { issue & ~can?(:create_issue) }.prevent :create_vulnerability_feedback

    rule do
      merge_request & ~can?(:create_merge_request_in)
    end.prevent :create_vulnerability_feedback

    # Prevent Security bot from creating vulnerability feedback
    # if auto-fix feature is disabled
    rule do
      merge_request &
        security_bot
    end.prevent :create_vulnerability_feedback

    rule { ~dismissal }.prevent :destroy_vulnerability_feedback, :update_vulnerability_feedback
    rule { issue & can?(:create_issue) }.enable :create_vulnerability_feedback

    rule { ~dismissal }.policy do
      prevent :_create_dismissal_vulnerability_feedback
      prevent :_destroy_dismissal_vulnerability_feedback
    end

    # Changing the status of a finding without a vulnerability needs admin_vulnerability,
    # and creating dismissal feedback for one also creates the vulnerability.
    rule { ~finding_has_vulnerability }.policy do
      prevent :_create_dismissal_vulnerability_feedback
      prevent :_destroy_dismissal_vulnerability_feedback
    end

    rule { can?(:_create_dismissal_vulnerability_feedback) }.enable :create_vulnerability_feedback
    rule { can?(:_destroy_dismissal_vulnerability_feedback) }.enable :destroy_vulnerability_feedback
  end
end

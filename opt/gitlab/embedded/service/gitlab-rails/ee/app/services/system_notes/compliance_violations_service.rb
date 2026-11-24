# frozen_string_literal: true

module SystemNotes # rubocop:disable Gitlab/BoundedContexts -- SystemNotes module already exists and holds the other services
  class ComplianceViolationsService < ::SystemNotes::BaseService
    def change_violation_status
      new_status = noteable.status.humanize
      create_note(NoteSummary.new(noteable, project, author, "changed status to #{new_status}", action: 'status'))
    end

    def link_issue(issue)
      body = "marked this compliance violation as related to #{issue.to_reference(full: true)}"
      create_note(NoteSummary.new(noteable, project, author, body, action: 'relate'))
    end

    def unlink_issue(issue)
      body = "removed the relation with #{issue.to_reference(full: true)}"
      create_note(NoteSummary.new(noteable, project, author, body, action: 'unrelate'))
    end
  end
end

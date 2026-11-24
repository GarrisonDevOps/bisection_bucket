# frozen_string_literal: true

module EE
  module IssueAssignee
    extend ActiveSupport::Concern

    prepended do
      after_commit :update_elasticsearch_index, on: [:create, :destroy]
    end

    def update_elasticsearch_index
      if issue.maintaining_elasticsearch? && issue.project&.maintaining_indexed_associations?
        issue.maintain_elasticsearch_update
        issue.maintain_elasticsearch_issue_notes_update # we need to propagate new permissions to notes
      end
    end
  end
end

# frozen_string_literal: true

module Resolvers
  class EpicIssuesResolver < BaseResolver
    include LooksAhead

    type Types::EpicIssueType.connection_type, null: true

    alias_method :epic, :object

    # because epic issues are ordered by EpicIssue's relative position,
    # we can not use batch loading to load epic issues for multiple epics at once
    # (assuming we don't load all issues for each epic but only a single page)
    def resolve_with_lookahead
      issues = apply_lookahead(
        ::WorkItems::LegacyEpics::WorkItemAsEpic.epic_issue_api_preloads(
          ::WorkItems::LegacyEpics::WorkItemAsEpic.new(epic.work_item).epic_issues
        )
      )
      ::Ability.issues_readable_by_user(issues, current_user)
    end

    private

    def preloads
      { start_date: [:dates_source] }
    end
  end
end

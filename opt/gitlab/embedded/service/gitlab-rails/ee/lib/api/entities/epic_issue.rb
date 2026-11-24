# frozen_string_literal: true

module API
  module Entities
    class EpicIssue < ::API::Entities::Issue
      expose :epic_issue_id,
        documentation: {
          desc: 'ID of the epic-issue relation',
          type: 'Integer',
          example: 123
        } do |issue, _options|
        # Null when the parent link has no legacy epic_issues row. Returning null degrades a single
        # child rather than failing the whole page: https://gitlab.com/gitlab-org/gitlab/-/issues/612058
        issue.parent_link.epic_issue&.id
      end

      expose :relative_position,
        documentation: {
          desc: 'Relative position of the issue in the epic tree',
          type: 'Integer',
          example: 0
        } do |issue, _options|
        issue.parent_link.relative_position
      end
    end
  end
end

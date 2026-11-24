# frozen_string_literal: true

module API
  module Entities
    class EpicIssueLink < Grape::Entity
      expose :id,
        documentation: {
          desc: 'ID of the epic-issue relation',
          type: 'Integer',
          example: 123
        }
      expose :relative_position,
        documentation: {
          desc: 'Relative position of the issue in the epic tree',
          type: 'Integer',
          example: 0
        }
      expose :epic, documentation: { type: '::API::Entities::Epic' } do |epic_issue_link, _options|
        ::API::Entities::Epic.represent(epic_issue_link.epic, with_reference: true)
      end
      expose :issue, using: ::API::Entities::IssueBasic
    end
  end
end

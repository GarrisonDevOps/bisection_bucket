# frozen_string_literal: true

module API
  module Entities
    class AiSuggestedReviewer < Grape::Entity
      expose :user, using: ::API::Entities::UserBasic
      expose :reason, documentation: { type: 'String', example: 'Authored most of the changed files.' }
      expose :approval_rule, documentation: { type: 'Hash' } do |suggested_reviewer|
        rule = suggested_reviewer.approval_rule
        next unless rule

        wrapped = ApprovalWrappedRule.wrap(suggested_reviewer.merge_request, rule)
        { id: rule.id, name: wrapped.name, section: wrapped.section }
      end
      expose :created_at, documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
    end
  end
end

# frozen_string_literal: true

module API
  module Entities
    class MergeRequestApprovalRule < ::API::Entities::ApprovalRule
      class SourceRule < Grape::Entity
        expose :approvals_required, documentation: { type: 'Integer', example: 2 }
      end

      expose :section, documentation: { type: 'String', example: 'Backend' }
      expose :source_rule, using: ::API::Entities::MergeRequestApprovalRule::SourceRule
      expose :overridden?, as: :overridden, documentation: { type: 'Boolean' }
    end
  end
end

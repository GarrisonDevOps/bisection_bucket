# frozen_string_literal: true

module API
  module Entities
    class ApprovalRuleShort < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the approval rule.' }
      expose :name, documentation: { type: 'String', example: 'QA', desc: 'Name of the approval rule.' }
      expose :rule_type, documentation: {
        type: 'String', example: 'regular',
        desc: 'Type of the approval rule. Possible values: `any_approver`, `code_owner`, `regular`, or ' \
          '`report_approver`.'
      }
    end
  end
end

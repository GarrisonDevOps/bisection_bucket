# frozen_string_literal: true

module API
  module Entities
    class MergeRequestApprovalState < Grape::Entity
      expose :approval_rules_overwritten, documentation: { type: 'Boolean' } do |approval_state, _options|
        approval_state.approval_rules_overwritten?
      end

      expose :wrapped_approval_rules, as: :rules,
        using: ::API::Entities::MergeRequestApprovalStateRule, documentation: { is_array: true }
    end
  end
end

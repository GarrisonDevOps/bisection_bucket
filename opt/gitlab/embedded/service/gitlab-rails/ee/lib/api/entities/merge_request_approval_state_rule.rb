# frozen_string_literal: true

module API
  module Entities
    class MergeRequestApprovalStateRule < ::API::Entities::MergeRequestApprovalRule
      expose :code_owner, documentation: { type: 'Boolean' }
      expose :approved_approvers, as: :approved_by,
        using: ::API::Entities::UserBasic, documentation: { is_array: true }
      expose :approved?, as: :approved, documentation: { type: 'Boolean' }
    end
  end
end

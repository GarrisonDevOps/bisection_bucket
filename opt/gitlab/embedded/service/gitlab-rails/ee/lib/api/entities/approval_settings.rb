# frozen_string_literal: true

module API
  module Entities
    class ApprovalSettings < Grape::Entity
      # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
      # Always return empty array
      expose :approvers, using: ::API::Entities::Approver, proc: ->(_) { [] }, documentation: { is_array: true }
      # Deprecated with epic https://gitlab.com/groups/gitlab-org/-/epics/19155
      # Always return empty array
      expose :approver_groups, using: ::API::Entities::ApproverGroup, proc: ->(_) { [] }, documentation: { is_array: true }
      expose :approvals_before_merge, documentation: { type: 'Integer' }

      expose :reset_approvals_on_push, documentation: { type: 'Boolean' }
      expose(:selective_code_owner_removals, documentation: { type: 'Boolean' }) do |project|
        project.project_setting.selective_code_owner_removals
      end

      expose :disable_overriding_approvers_per_merge_request?,
        as: :disable_overriding_approvers_per_merge_request,
        documentation: { type: 'Boolean' }

      expose :merge_requests_author_approval?,
        as: :merge_requests_author_approval,
        documentation: { type: 'Boolean' }

      expose :merge_requests_disable_committers_approval?,
        as: :merge_requests_disable_committers_approval,
        documentation: { type: 'Boolean' }

      expose :require_password_to_approve?,
        as: :require_password_to_approve,
        documentation: { type: 'Boolean' }

      expose :require_reauthentication_to_approve?,
        as: :require_reauthentication_to_approve,
        documentation: { type: 'Boolean' }
    end
  end
end

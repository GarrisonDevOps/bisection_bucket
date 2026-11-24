# frozen_string_literal: true

module API
  module Entities
    # Being used in private project-level approvals API.
    #
    # To be removed in https://gitlab.com/gitlab-org/gitlab/issues/13574.
    class ProjectApprovalSettings < Grape::Entity
      expose :rules,
        using: ::API::Entities::ProjectApprovalSettingRule,
        documentation: { is_array: true } do |project, options|
        project.visible_approval_rules(target_branch: options[:target_branch])
      end

      expose :min_fallback_approvals, as: :fallback_approvals_required, documentation: { type: 'Integer' }
    end
  end
end

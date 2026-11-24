# frozen_string_literal: true

module API
  module Entities
    # Being used in private project-level approvals API.
    # This overrides the `eligible_approvers` to be exposed as `approvers`.
    #
    # To be removed in https://gitlab.com/gitlab-org/gitlab/issues/13574.
    class ProjectApprovalSettingRule < ::API::Entities::ProjectApprovalRule
      expose :approvers, using: ::API::Entities::UserBasic, override: true, documentation: { is_array: true }
      expose :scanners, override: true, documentation: { type: 'String', is_array: true }
      expose :vulnerabilities_allowed, override: true, documentation: { type: 'Integer' }
      expose :severity_levels, override: true, documentation: { type: 'String', is_array: true }
      expose :vulnerability_states, override: true, documentation: { type: 'String', is_array: true }
    end
  end
end

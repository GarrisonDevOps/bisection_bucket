# frozen_string_literal: true

module Types
  module PermissionTypes
    class PipelineSecurityReportFinding < BasePermissionType
      graphql_name 'PipelineSecurityReportFindingPermissions'
      description 'Check permissions for the current user on a vulnerability finding.'

      abilities :admin_vulnerability, :create_issue, :confirm_vulnerability, :dismiss_vulnerability,
        :resolve_vulnerability, :revert_vulnerability, :update_vulnerability_severity
    end
  end
end

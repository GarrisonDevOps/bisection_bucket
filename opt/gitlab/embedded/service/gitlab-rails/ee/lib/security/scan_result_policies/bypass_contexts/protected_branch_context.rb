# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module BypassContexts
      class ProtectedBranchContext < BaseContext
        def suppress_reason_required_error?
          true
        end

        def audit_name(_bypass_type)
          'security_policy_protected_branch_bypass'
        end

        def audit_message(branch_name:, project:, user:, security_policy:, **_kwargs)
          <<~MSG.squish
            Protected branch restrictions on '#{branch_name}' for project '#{project.full_path}'
            have been bypassed by #{user.name} using security policy '#{security_policy.name}'
          MSG
        end

        def enrich_audit_details(details, project:, user:)
          details.merge(
            project_path: project.full_path,
            user_name: user.name,
            protected_branch_bypass: true
          )
        end

        def include_bypass_reason_in_details?
          true
        end
      end
    end
  end
end

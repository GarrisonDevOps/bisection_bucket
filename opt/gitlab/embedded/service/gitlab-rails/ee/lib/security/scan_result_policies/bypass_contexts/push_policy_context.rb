# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module BypassContexts
      class PushPolicyContext < BaseContext
        def audit_name(bypass_type)
          "security_policy_#{bypass_type}_push_bypass"
        end

        def audit_message(bypass_type:, identifier:, branch_name:, project:, **_kwargs)
          <<~MSG.squish
            Branch push restriction on '#{branch_name}' for project '#{project.full_path}'
            has been bypassed by #{bypass_type} with ID: #{identifier}
          MSG
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module SingleChangeAccess
        extend ActiveSupport::Concern
        include ::Gitlab::Utils::StrongMemoize

        def security_policy_bypass
          ::Security::ScanResultPolicies::CombinedBypassChecker.new(
            project: project,
            user_access: user_access,
            branch_name: branch_name,
            push_options: push_options
          )
        end
        strong_memoize_attr :security_policy_bypass
      end
    end
  end
end

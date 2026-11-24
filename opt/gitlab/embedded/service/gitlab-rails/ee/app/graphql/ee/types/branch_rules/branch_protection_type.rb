# frozen_string_literal: true

module EE
  module Types
    module BranchRules
      module BranchProtectionType
        extend ActiveSupport::Concern

        prepended do
          field :unprotect_access_levels,
            type: ::Types::BranchProtections::UnprotectAccessLevelType.connection_type,
            null: true,
            description: 'Details about who can unprotect the branch.'

          field :code_owner_approval_required,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Enforce code owner approvals before allowing a merge.'

          field :warn_modification_blocked_by_policy,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates if a warn mode security policy would prevent modification.',
            calls_gitaly: true

          field :warn_protected_from_push_by_security_policy,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates if a warn mode security policy would prevent push or force push.',
            calls_gitaly: true

          field :modification_blocked_by_policy,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates if a security policy prevents modification.',
            calls_gitaly: true

          field :protected_from_push_by_security_policy,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates if a security policy prevents push or force push.',
            calls_gitaly: true

          field :is_group_level,
            type: GraphQL::Types::Boolean,
            null: false,
            description: 'Indicates whether the branch protection rule was created at the group level.',
            method: :group_level?,
            experiment: { milestone: '18.3' }
        end

        def modification_blocked_by_policy
          object.modification_blocked_by_policy(current_user)
        end

        def warn_modification_blocked_by_policy
          object.warn_modification_blocked_by_policy(current_user)
        end

        def push_access_levels
          return no_one_push_access_level if object.protected_from_push_by_security_policy?

          object.push_access_levels
        end

        private

        def no_one_push_access_level
          [
            ::ProtectedBranch::PushAccessLevel.new(
              access_level: ::Gitlab::Access::NO_ACCESS,
              protected_branch: object
            )
          ]
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Types
    module Projects
      module BranchRuleType
        extend ActiveSupport::Concern

        prepended do
          field :approval_rules,
            type: ::Types::BranchRules::ApprovalProjectRuleType.connection_type,
            authorize: :manage_merge_request_settings, # rubocop:disable Gitlab/Authz/PermissionCheck -- Existing permission naming, needs to be renamed everywhere
            method: :approval_project_rules,
            null: true,
            description: 'Merge request approval rules configured for the branch rule.'

          field :external_status_checks,
            type: ::Types::BranchRules::ExternalStatusCheckType.connection_type,
            authorize: :read_external_status_check,
            null: true,
            description: 'External status checks configured for the branch rule.'

          field :is_group_level,
            type: GraphQL::Types::Boolean,
            null: false,
            method: :group_level?,
            description: 'Indicates whether the branch rule was created at the group level. ' \
              'Unlike the equivalent field on `BranchProtection`, this field is readable by ' \
              'every user who can read the branch rule.',
            experiment: { milestone: '19.3' }
        end
      end
    end
  end
end

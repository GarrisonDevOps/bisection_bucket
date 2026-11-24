# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class ApprovalPolicyAttributesType < BaseObject
      graphql_name 'ApprovalPolicyAttributesType'
      description 'Represents policy fields related to the approval policy.'

      field :action_approvers, [::Types::SecurityOrchestration::PolicyApproversType], null: true,
        description: 'Multiple approvers action.'
      field :all_group_approvers, [::Types::SecurityOrchestration::ApprovalGroupType],
        null: true,
        description: 'All potential approvers of the group type, including groups inaccessible to the user.'
      field :custom_roles, [GraphQL::Schema::LateBoundType.new('MemberRole')],
        null: true,
        description: 'Approvers of the custom role type. Users belonging to these role(s) alone will be approvers.'
      field :deprecated_properties, [::GraphQL::Types::String], null: true,
        description: 'All deprecated properties in the policy.',
        experiment: { milestone: '16.10' }
      field :enforcement_type, ::Types::SecurityOrchestration::PolicyEnforcementTypeEnum, null: true,
        description: 'Enforcement type of the policy. Can be "enforce" or "warn".'
      field :role_approvers, [::Types::MemberAccessLevelNameEnum],
        null: true,
        description: 'Approvers of the role type. Users belonging to these role(s) alone will be approvers.'
      field :source, Types::SecurityOrchestration::SecurityPolicySourceType,
        null: false,
        description: 'Source of the policy. Its fields depend on the source type.'
      field :user_approvers, [::Types::UserType], null: true, description: 'Approvers of the user type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end

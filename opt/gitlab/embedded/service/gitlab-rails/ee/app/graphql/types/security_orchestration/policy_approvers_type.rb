# frozen_string_literal: true

module Types
  module SecurityOrchestration # rubocop:disable Gitlab/BoundedContexts -- Existing module
    # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
    class PolicyApproversType < BaseObject
      graphql_name 'PolicyApproversType'
      description 'Multiple approvers action'

      field :all_groups, [::Types::SecurityOrchestration::ApprovalGroupType], null: true,
        description: 'All potential approvers of the group type, including groups inaccessible to the user.'
      field :custom_roles, [GraphQL::Schema::LateBoundType.new('MemberRole')],
        null: true,
        description: 'Approvers of the custom role type. Users belonging to these role(s) alone will be approvers.'
      field :roles, [::Types::MemberAccessLevelNameEnum],
        null: true,
        description: 'Approvers of the role type. Users belonging to these role(s) alone will be approvers.'
      field :users, [::Types::UserType], null: true, description: 'Approvers of the user type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end

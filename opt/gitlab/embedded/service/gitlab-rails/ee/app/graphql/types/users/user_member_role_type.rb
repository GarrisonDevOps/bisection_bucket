# frozen_string_literal: true

module Types
  module Users
    class UserMemberRoleType < BaseObject
      graphql_name 'UserMemberRole'

      authorize :admin_member_role

      field :id,
        type: ::Types::GlobalIDType, null: false, description: 'Global ID of the user member role association.'

      field :member_role, ::Types::MemberRoles::MemberRoleType,
        null: false, description: 'Member Role to which the user belongs.'

      field :user, UserType,
        null: false, description: 'User to which the member role belongs.'
    end
  end
end

# frozen_string_literal: true

module EE
  module Types
    module BranchProtections
      module BaseAccessLevelType
        extend ActiveSupport::Concern

        prepended do
          field :user,
            ::Types::AccessLevels::UserType,
            null: true,
            description: 'User associated with the access level.'

          field :group,
            ::Types::AccessLevels::GroupType,
            null: true,
            description: 'Group associated with the access level.'

          field :member_role,
            ::Types::MemberRoles::MemberRoleType,
            null: true,
            description: 'Custom role associated with the access level.'

          def member_role
            object.member_role if object.custom_roles_licensed?
          end
        end
      end
    end
  end
end

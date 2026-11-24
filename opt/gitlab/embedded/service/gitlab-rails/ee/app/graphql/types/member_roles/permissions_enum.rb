# frozen_string_literal: true

module Types
  module MemberRoles
    class PermissionsEnum < BaseEnum
      graphql_name 'MemberRolePermission'
      description 'Member role permission'

      MemberRole.all_customizable_permissions.each_pair do |key, value|
        value key.upcase, value: key, description: value[:description]
      end
    end
  end
end

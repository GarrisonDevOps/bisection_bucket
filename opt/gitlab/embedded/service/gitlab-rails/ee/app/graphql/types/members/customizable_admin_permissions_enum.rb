# frozen_string_literal: true

module Types
  module Members
    class CustomizableAdminPermissionsEnum < BaseEnum
      graphql_name 'MemberRoleAdminPermission'
      description 'Member role admin permission'

      ::Gitlab::CustomRoles::Definition.admin.each_pair do |key, attrs|
        value key.upcase, value: key, description: attrs[:description]
      end
    end
  end
end

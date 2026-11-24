# frozen_string_literal: true

module Types
  module Members
    class CustomizableStandardPermissionsEnum < BaseEnum
      graphql_name 'MemberRoleStandardPermission'
      description 'Member role standard permission'

      MemberRole.all_customizable_standard_permissions.each_pair do |key, attrs|
        value key.upcase, value: key, description: attrs[:description]
      end
    end
  end
end

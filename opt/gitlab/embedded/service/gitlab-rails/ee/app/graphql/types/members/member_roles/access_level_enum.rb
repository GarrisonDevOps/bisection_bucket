# frozen_string_literal: true

module Types
  module Members
    module MemberRoles
      class AccessLevelEnum < BaseEnum
        graphql_name 'MemberRolesAccessLevel'
        description 'Access level of a group or project member'

        def self.descriptions
          Gitlab::Access.option_descriptions
        end

        Gitlab::Access.options_for_custom_roles.each do |key, value|
          value key.upcase.tr(' ', '_'), value: value, description: descriptions[value]
        end
      end
    end
  end
end

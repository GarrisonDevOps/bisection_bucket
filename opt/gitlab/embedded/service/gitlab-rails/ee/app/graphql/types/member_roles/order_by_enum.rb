# frozen_string_literal: true

module Types
  module MemberRoles
    class OrderByEnum < BaseEnum
      graphql_name 'MemberRolesOrderBy'
      description 'Values for ordering member roles by a specific field'

      value 'NAME', 'Ordered by name.', value: :name
      value 'CREATED_AT', 'Ordered by creation time.', value: :created_at
      value 'ID', 'Ordered by id.', value: :id
    end
  end
end

# frozen_string_literal: true

module Types
  module SecretsManagement
    module Permissions
      class PrincipalInputType < BaseInputObject
        graphql_name 'PrincipalInput'
        description 'Representation of who is provided access to. For eg: User/Role/MemberRole.'

        argument :id, GraphQL::Types::Int,
          required: true,
          description: 'ID of the principal.'

        argument :type, Types::SecretsManagement::Permissions::PrincipalTypeEnum,
          required: true,
          description: 'Type of the principal.'
      end
    end
  end
end

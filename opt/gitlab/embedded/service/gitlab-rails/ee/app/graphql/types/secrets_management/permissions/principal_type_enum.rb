# frozen_string_literal: true

module Types
  module SecretsManagement
    module Permissions
      class PrincipalTypeEnum < BaseEnum
        graphql_name 'PrincipalType'
        description 'Types of principal that can have secrets permissions'

        value 'USER', 'user.',
          value: ::SecretsManagement::BaseSecretsPermission::PRINCIPAL_TYPES[:user]
        value 'MEMBER_ROLE', 'member role.',
          value: ::SecretsManagement::BaseSecretsPermission::PRINCIPAL_TYPES[:member_role]
        value 'ROLE', 'predefined role.',
          value: ::SecretsManagement::BaseSecretsPermission::PRINCIPAL_TYPES[:role]
      end
    end
  end
end

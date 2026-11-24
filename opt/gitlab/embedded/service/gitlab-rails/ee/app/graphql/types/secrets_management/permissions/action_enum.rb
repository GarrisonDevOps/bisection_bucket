# frozen_string_literal: true

module Types
  module SecretsManagement
    module Permissions
      class ActionEnum < BaseEnum
        graphql_name 'SecretsManagementAction'
        description 'Actions that can be performed on secrets'

        value 'READ', description: 'Read secrets.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:read]
        value 'READ_VALUE', description: 'Read secret values.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:read_value]
        value 'CREATE', description: 'Create secrets without updating existing ones.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:create]
        value 'UPDATE', description: 'Update existing secrets.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:update]
        value 'WRITE', description: 'Create and update secrets.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:write],
          deprecated: { reason: 'Use `CREATE` and `UPDATE`. Planned for removal in GitLab 20.0', milestone: '19.6' }
        value 'DELETE', description: 'Delete secrets.',
          value: ::SecretsManagement::BaseSecretsPermission::ACTIONS[:delete]
      end
    end
  end
end

# frozen_string_literal: true

module Types
  module SecretsManagement
    class SecretStatusEnum < BaseEnum
      graphql_name 'SecretStatus'
      description 'Status of secret'

      value 'COMPLETED', 'Secret is complete.', value: ::SecretsManagement::SecretStatus::STATUSES[:completed]
      value 'CREATE_STALE', 'Secret creation appears stale (started long ago or missing completion timestamp).',
        value: ::SecretsManagement::SecretStatus::STATUSES[:create_stale]
      value 'UPDATE_STALE', 'Secret update appears stale (started long ago or missing completion timestamp).',
        value: ::SecretsManagement::SecretStatus::STATUSES[:update_stale]
      value 'CREATE_IN_PROGRESS', 'Secret creation is in progress.',
        value: ::SecretsManagement::SecretStatus::STATUSES[:create_in_progress]
      value 'UPDATE_IN_PROGRESS', 'Secret update is in progress.',
        value: ::SecretsManagement::SecretStatus::STATUSES[:update_in_progress]
    end
  end
end

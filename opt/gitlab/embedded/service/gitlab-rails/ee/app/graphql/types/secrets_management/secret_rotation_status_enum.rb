# frozen_string_literal: true

module Types
  module SecretsManagement
    class SecretRotationStatusEnum < BaseEnum
      graphql_name 'SecretRotationStatus'
      description 'Status of secret rotation'

      value 'OK', 'Rotation is not due soon.', value: ::SecretsManagement::BaseSecretRotationInfo::STATUSES[:ok]
      value 'APPROACHING', 'Rotation is due within 7 days.',
        value: ::SecretsManagement::BaseSecretRotationInfo::STATUSES[:approaching]
      value 'OVERDUE', 'Rotation is overdue (reminder was sent).',
        value: ::SecretsManagement::BaseSecretRotationInfo::STATUSES[:overdue]
    end
  end
end

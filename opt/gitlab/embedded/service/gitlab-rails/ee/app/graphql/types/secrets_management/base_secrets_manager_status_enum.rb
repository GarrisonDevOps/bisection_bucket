# frozen_string_literal: true

module Types
  module SecretsManagement
    module BaseSecretsManagerStatusEnum
      extend ActiveSupport::Concern

      included do
        value 'PROVISIONING', 'Secrets manager is being provisioned.',
          value: ::SecretsManagement::ProjectSecretsManager::STATUSES[:provisioning]

        value 'ACTIVE', 'Secrets manager has been provisioned and enabled.',
          value: ::SecretsManagement::ProjectSecretsManager::STATUSES[:active]

        value 'DEPROVISIONING', 'Secrets manager is being deprovisioned.',
          value: ::SecretsManagement::ProjectSecretsManager::STATUSES[:deprovisioning]
      end
    end
  end
end

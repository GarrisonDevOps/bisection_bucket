# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        ##
        # Entry that represents a secret definition.
        #
        class Secret < ::Gitlab::Config::Entry::Node
          include ::Gitlab::Config::Entry::Configurable
          include ::Gitlab::Config::Entry::Attributable

          ALLOWED_KEYS = %i[vault file azure_key_vault gcp_secret_manager gitlab_secrets_manager token
            aws_secrets_manager].freeze
          SUPPORTED_PROVIDERS = %i[vault azure_key_vault gcp_secret_manager gitlab_secrets_manager
            aws_secrets_manager].freeze

          attributes ALLOWED_KEYS

          entry :vault, Entry::Vault::Secret, description: 'Vault secrets engine configuration'
          entry :aws_secrets_manager, Entry::AwsSecretsManager::Secret, description: 'AWS engine configuration'
          entry :file, ::Gitlab::Config::Entry::Boolean, description: 'Should the created variable be of file type'
          entry :azure_key_vault, Entry::AzureKeyVault::Secret, description: 'Azure Key Vault configuration'
          entry :gcp_secret_manager, Entry::GcpSecretManager::Secret, description: 'GCP Secrets Manager configuration'
          entry :gitlab_secrets_manager, Entry::GitlabSecretsManager::Secret,
            description: 'Gitlab Secrets Manager configuration'

          validations do
            validates :config, allowed_keys: ALLOWED_KEYS, only_one_of_keys: SUPPORTED_PROVIDERS
            validates :token, type: String, allow_nil: true
            validates :token, presence: {
              if: ->(node) { node.config.is_a?(Hash) && node.config[:gcp_secret_manager].present? },
              message: 'is required with gcp secrets manager'
            }
          end

          def value
            {
              vault: vault_value,
              gitlab_secrets_manager: gitlab_secrets_manager_value,
              aws_secrets_manager: aws_secrets_manager_value,
              gcp_secret_manager: gcp_secret_manager_value,
              azure_key_vault: azure_key_vault_value,
              file: file_value,
              token: token
            }.compact
          end
        end
      end
    end
  end
end

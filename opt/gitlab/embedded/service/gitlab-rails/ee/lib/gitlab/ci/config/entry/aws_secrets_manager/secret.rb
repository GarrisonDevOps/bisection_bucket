# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        module AwsSecretsManager
          ##
          # Entry that represents AWS SSM ParameterStore.
          #
          class Secret < ::Gitlab::Config::Entry::Simplifiable
            strategy :StringStrategy, if: ->(config) { config.is_a?(String) }
            strategy :HashStrategy, if: ->(config) { config.is_a?(Hash) }

            class UnknownStrategy < ::Gitlab::Config::Entry::Node
              def errors
                ["#{location} should be a hash or a string"]
              end
            end

            class StringStrategy < ::Gitlab::Config::Entry::Node
              include ::Gitlab::Config::Entry::Validatable

              validations do
                validates :config, presence: true
                validates :config, type: String,
                  format: { with: /\A[^#]*(#[^#]*)?\z/, message: "must contain at most one '#'" }
              end

              def value
                # expect to return 1 element for secret without field and 2 elements for secret with field
                parts = config.split('#')

                # input "/my/secret"
                if parts.size == 1
                  {
                    secret_id: parts[0]
                  }
                # input "/my/secret#field"
                else
                  {
                    secret_id: parts[0],
                    field: parts[1]
                  }
                end
              end
            end

            class HashStrategy < ::Gitlab::Config::Entry::Node
              include ::Gitlab::Config::Entry::Validatable
              include ::Gitlab::Config::Entry::Attributable

              ALLOWED_KEYS = %i[secret_id region version_id version_stage role_arn role_session_name field].freeze

              attributes ALLOWED_KEYS

              validations do
                validates :config, type: Hash, allowed_keys: ALLOWED_KEYS
                # Required fields
                validates :secret_id, type: String, presence: true

                # Optional fields
                validates :region, type: String, allow_nil: true
                validates :version_id, type: String, allow_nil: true
                validates :version_stage, type: String, allow_nil: true
                validates :role_arn, type: String, allow_nil: true
                validates :role_session_name, type: String, allow_nil: true
                validates :field, type: String, allow_nil: true
              end

              def value
                {
                  secret_id: secret_id,
                  version_id: version_id,
                  version_stage: version_stage,
                  region: region,
                  role_arn: role_arn,
                  field: field,
                  role_session_name: role_session_name
                }
              end
            end
          end
        end
      end
    end
  end
end

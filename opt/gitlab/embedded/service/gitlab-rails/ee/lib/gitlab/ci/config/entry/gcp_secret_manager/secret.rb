# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        module GcpSecretManager
          class Secret < ::Gitlab::Config::Entry::Node
            include ::Gitlab::Config::Entry::Validatable
            include ::Gitlab::Config::Entry::Attributable

            ALLOWED_KEYS = %i[name version].freeze
            DEFAULT_VERSION = 'latest'

            attributes ALLOWED_KEYS

            validations do
              validates :config, type: Hash, allowed_keys: ALLOWED_KEYS
              validates :name, presence: true, type: String
              validates :version, alphanumeric: true, allow_nil: true
            end

            def value
              {
                name: name,
                version: version&.to_s || DEFAULT_VERSION
              }
            end
          end
        end
      end
    end
  end
end

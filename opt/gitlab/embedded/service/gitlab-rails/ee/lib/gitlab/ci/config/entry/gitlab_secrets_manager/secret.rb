# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        module GitlabSecretsManager
          class Secret < ::Gitlab::Config::Entry::Node
            include ::Gitlab::Config::Entry::Validatable
            include ::Gitlab::Config::Entry::Attributable

            ALLOWED_KEYS = %i[name source].freeze

            attributes ALLOWED_KEYS

            validations do
              validates :config, type: Hash, allowed_keys: ALLOWED_KEYS
              validates :name, presence: true, type: String,
                format: { with: ::SecretsManagement::BaseSecret::SECRET_NAME_FORMAT,
                          message: ::SecretsManagement::BaseSecret::SECRET_NAME_FORMAT_MESSAGE }
              validates :source, type: String, allow_nil: true,
                format: { with: %r{\A(project|group/[a-zA-Z0-9_\-\./]+)\z},
                          message: "must follow the format group/group_full_path or 'project'" }
            end

            def value
              {
                name: name,
                source: source
              }.compact
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        ##
        # Entry that represents workload identity settings.
        #
        class Identity < ::Gitlab::Config::Entry::Node
          include ::Gitlab::Config::Entry::Validatable

          ALLOWED_IDENTITY_PROVIDERS = %w[google_cloud].freeze

          validations do
            validates :config, type: String, inclusion: {
              in: ALLOWED_IDENTITY_PROVIDERS,
              message: "should be one of: #{ALLOWED_IDENTITY_PROVIDERS.join(', ')}"
            }
          end
        end
      end
    end
  end
end

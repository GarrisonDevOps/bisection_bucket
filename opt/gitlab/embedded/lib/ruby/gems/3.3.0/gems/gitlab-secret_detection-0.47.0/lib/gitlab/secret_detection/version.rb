# frozen_string_literal: true

module Gitlab
  module SecretDetection
    class Gem
      # Ensure to maintain the same version in CHANGELOG file.
      # More details available under 'Release Process' section in the README.md file.
      VERSION = "0.47.0"

      # SD_ENV env var is used to determine which environment the
      # server is running. This var is defined in `.runway/env-<env>.yml` files.
      def self.local_env?
        ENV.fetch('SD_ENV', 'localhost') == 'localhost'
      end
    end
  end
end

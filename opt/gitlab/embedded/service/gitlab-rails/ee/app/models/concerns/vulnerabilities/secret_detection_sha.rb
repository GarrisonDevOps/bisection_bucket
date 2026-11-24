# frozen_string_literal: true

module Vulnerabilities
  module SecretDetectionSha
    extend ActiveSupport::Concern

    def secret_detection_sha
      return unless secret_detection?

      return unless location

      commit_sha = location.dig(*commit_sha_location_keys)
      return if commit_sha == ::Vulnerabilities::Finding::SECRET_DETECTION_DEFAULT_COMMIT_SHA

      commit_sha
    end

    private

    def commit_sha_location_keys
      %w[commit sha]
    end
  end
end

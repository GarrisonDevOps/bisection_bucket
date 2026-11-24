# frozen_string_literal: true

module Geo
  module Tools
    # SPIKE (gitlab-org/gitlab#602803): entry point to the known-error catalog, wrapping
    # each Geo::Errors::ErrorType in a KnownError that adds detection behaviour.
    module KnownErrors
      module_function

      # options are forwarded to the resolution strategy, so a caller can pass per-run knobs
      # (for example min_retry_count) without knowing which strategy backs the entry.
      def catalog(**options)
        Geo::Errors::ErrorType.all.map { |error_type| KnownError.new(error_type, **options) }
      end

      def find(key, **options)
        error_type = Geo::Errors::ErrorType.find_by(name: key.to_s)
        KnownError.new(error_type, **options) if error_type
      end
    end
  end
end

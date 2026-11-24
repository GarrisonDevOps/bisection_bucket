# frozen_string_literal: true

module API
  module Helpers
    module Packages
      module Conan
        module ApiErrorFormatter
          def render_structured_api_error!(hash, status)
            super(with_conan_errors(hash, Rack::Utils.status_code(status)), status)
          end

          private

          def api_error_body(status_code, message)
            with_conan_errors(super, status_code)
          end

          # Conan's response_to_str() natively parses the "errors" array format,
          # producing clean user-facing messages instead of raw JSON dumps.
          def with_conan_errors(hash, status_code)
            return hash unless status_code >= 400
            return hash unless Feature.enabled?(:conan_structured_error_responses, Feature.current_request)

            hash = hash.with_indifferent_access
            stripped = hash[:message].to_s.sub(/\A#{status_code}\s+/, '')
            hash[:errors] = [{ 'status' => status_code, 'message' => stripped }]
            hash
          end
        end
      end
    end
  end
end

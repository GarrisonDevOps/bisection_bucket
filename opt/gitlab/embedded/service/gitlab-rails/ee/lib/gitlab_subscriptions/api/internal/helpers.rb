# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Internal
      module Helpers
        def jwt_request?
          headers[Auth::INTERNAL_API_REQUEST_HEADER].present?
        end

        def authenticate_from_jwt!
          unauthorized! unless Auth.verify_api_request(headers)
        end
      end
    end
  end
end

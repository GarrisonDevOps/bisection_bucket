# frozen_string_literal: true

module ArtifactRegistry
  module Errors
    class Error < StandardError
      attr_reader :status, :request_id

      def initialize(message = nil, status: nil, request_id: nil)
        super(message)
        @status = status
        @request_id = request_id
      end
    end

    AuthorizationError = Class.new(Error)
    UnavailableError = Class.new(Error)
    ConfigurationError = Class.new(Error)

    class ApiError < Error
      attr_reader :code, :details

      def initialize(message = nil, status: nil, code: nil, request_id: nil, details: nil)
        super(message, status: status, request_id: request_id)
        @code = code
        @details = details
      end
    end
  end
end

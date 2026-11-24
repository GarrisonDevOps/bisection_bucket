# frozen_string_literal: true

module Bitbucket
  module Error
    class InvalidResponse < StandardError
      attr_reader :http_status

      def initialize(message, http_status: nil)
        @http_status = http_status
        super(message)
      end
    end
  end
end

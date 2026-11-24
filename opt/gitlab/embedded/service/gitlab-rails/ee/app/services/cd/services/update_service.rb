# frozen_string_literal: true

module Cd
  module Services
    class UpdateService
      def initialize(service, current_user: nil, params: {})
        @service = service
        @current_user = current_user
        @params = params.dup
      end

      def execute
        if service.update(params)
          ServiceResponse.success(payload: { service: service })
        else
          ServiceResponse.error(
            message: service.errors.full_messages,
            payload: { service: service }
          )
        end
      end

      private

      attr_reader :service, :current_user, :params
    end
  end
end

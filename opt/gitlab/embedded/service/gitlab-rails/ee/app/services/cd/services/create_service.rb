# frozen_string_literal: true

module Cd
  module Services
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        service = ::Cd::Service.new(params.merge(application: parent, organization: parent.organization))

        if service.save
          ServiceResponse.success(payload: { service: service })
        else
          ServiceResponse.error(
            message: service.errors.full_messages,
            payload: { service: service }
          )
        end
      end

      private

      attr_reader :parent, :current_user, :params
    end
  end
end

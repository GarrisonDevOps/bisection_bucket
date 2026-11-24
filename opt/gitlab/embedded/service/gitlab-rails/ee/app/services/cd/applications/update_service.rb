# frozen_string_literal: true

module Cd
  module Applications
    class UpdateService
      def initialize(application, current_user: nil, params: {})
        @application = application
        @current_user = current_user
        @params = params.dup
      end

      def execute
        if application.update(params)
          ServiceResponse.success(payload: { application: application })
        else
          ServiceResponse.error(
            message: application.errors.full_messages,
            payload: { application: application }
          )
        end
      end

      private

      attr_reader :application, :current_user, :params
    end
  end
end

# frozen_string_literal: true

module Cd
  module Environments
    class UpdateService
      def initialize(environment, current_user: nil, params: {})
        @environment = environment
        @current_user = current_user
        @params = params.dup
      end

      def execute
        if environment.update(params)
          ServiceResponse.success(payload: { environment: environment })
        else
          ServiceResponse.error(
            message: environment.errors.full_messages,
            payload: { environment: environment }
          )
        end
      end

      private

      attr_reader :environment, :current_user, :params
    end
  end
end

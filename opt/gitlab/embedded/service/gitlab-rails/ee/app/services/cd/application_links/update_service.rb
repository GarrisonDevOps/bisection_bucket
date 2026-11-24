# frozen_string_literal: true

module Cd
  module ApplicationLinks
    class UpdateService
      def initialize(application_link, current_user: nil, params: {})
        @application_link = application_link
        @current_user = current_user
        @params = params.dup
      end

      def execute
        if application_link.update(params)
          ServiceResponse.success(payload: { application_link: application_link })
        else
          ServiceResponse.error(
            message: application_link.errors.full_messages,
            payload: { application_link: application_link }
          )
        end
      end

      private

      attr_reader :application_link, :current_user, :params
    end
  end
end

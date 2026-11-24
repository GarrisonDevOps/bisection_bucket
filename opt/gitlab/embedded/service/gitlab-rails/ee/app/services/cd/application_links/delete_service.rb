# frozen_string_literal: true

module Cd
  module ApplicationLinks
    class DeleteService
      def initialize(application_link, current_user: nil)
        @application_link = application_link
        @current_user = current_user
      end

      def execute
        if application_link.destroy
          ServiceResponse.success(payload: { application_link: application_link })
        else
          ServiceResponse.error(
            message: application_link.errors.full_messages,
            payload: { application_link: application_link }
          )
        end
      end

      private

      attr_reader :application_link, :current_user
    end
  end
end

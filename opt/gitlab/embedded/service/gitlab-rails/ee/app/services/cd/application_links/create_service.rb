# frozen_string_literal: true

module Cd
  module ApplicationLinks
    class CreateService
      def initialize(parent:, current_user: nil, params: {})
        @parent = parent
        @current_user = current_user
        @params = params.dup
      end

      def execute
        application_link = ::Cd::ApplicationLink.new(
          params.merge(application: parent, organization: parent.organization)
        )

        if application_link.save
          ServiceResponse.success(payload: { application_link: application_link })
        else
          ServiceResponse.error(
            message: application_link.errors.full_messages,
            payload: { application_link: application_link }
          )
        end
      end

      private

      attr_reader :parent, :current_user, :params
    end
  end
end

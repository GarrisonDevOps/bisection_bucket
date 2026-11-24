# frozen_string_literal: true

module EE
  module Admin
    module ApplicationController
      # This will set an instance variable that will be read by EE::ApplicationHelper
      #
      # @see EE::ApplicationHelper
      def limited_actions_message!
        @limited_actions_message = true
      end
    end
  end
end

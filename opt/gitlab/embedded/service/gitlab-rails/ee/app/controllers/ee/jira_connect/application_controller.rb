# frozen_string_literal: true

module EE
  module JiraConnect
    module ApplicationController
      extend ActiveSupport::Concern

      prepended do
        before_action :check_if_blocked_by_settings
      end

      private

      def check_if_blocked_by_settings
        return unless ::Integrations::JiraCloudApp.blocked_by_settings?(log: true)

        render_404
      end
    end
  end
end

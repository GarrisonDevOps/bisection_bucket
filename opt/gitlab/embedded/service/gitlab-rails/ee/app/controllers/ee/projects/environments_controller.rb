# frozen_string_literal: true

module EE
  module Projects
    module EnvironmentsController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        before_action :authorize_create_environment_terminal!, only: [:terminal, :terminal_websocket_authorize]
      end

      private

      override :deployments
      def deployments
        super.with_approvals
      end

      def authorize_create_environment_terminal!
        render_404 unless can?(current_user, :create_environment_terminal, environment)
      end
    end
  end
end

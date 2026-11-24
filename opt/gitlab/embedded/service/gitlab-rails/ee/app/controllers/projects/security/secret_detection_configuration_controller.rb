# frozen_string_literal: true

module Projects
  module Security
    class SecretDetectionConfigurationController < Projects::ApplicationController
      include SecurityAndCompliancePermissions

      before_action :ensure_feature_is_available!
      before_action :authorize_read_project_security_exclusions!

      feature_category :secret_detection
      urgency :low, [:show]

      def show; end

      private

      def ensure_feature_is_available!
        not_found unless project.licensed_feature_available?(:secret_push_protection)
      end

      def authorize_read_project_security_exclusions!
        not_found unless can?(current_user, :read_project_security_exclusions, project)
      end
    end
  end
end

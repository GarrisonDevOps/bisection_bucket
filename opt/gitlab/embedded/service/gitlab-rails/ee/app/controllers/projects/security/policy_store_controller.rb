# frozen_string_literal: true

module Projects
  module Security
    class PolicyStoreController < Projects::ApplicationController
      include SecurityPoliciesPermissions

      before_action :ensure_policy_store_experiment_active!
      before_action :authorize_read_govern_policy!

      feature_category :security_policy_management
      urgency :low, [:index]

      def index
        render :index, locals: { project: project }
      end

      private

      def container
        project
      end

      def ensure_policy_store_experiment_active!
        render_404 unless project.policy_store_experiment_active?
      end

      def authorize_read_govern_policy!
        render_404 unless can?(current_user, :read_govern_policy, project)
      end
    end
  end
end

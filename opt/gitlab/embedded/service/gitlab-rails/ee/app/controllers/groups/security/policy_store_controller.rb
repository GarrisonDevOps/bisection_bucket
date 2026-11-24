# frozen_string_literal: true

module Groups
  module Security
    class PolicyStoreController < Groups::ApplicationController
      include SecurityPoliciesPermissions

      before_action :ensure_policy_store_experiment_active!
      before_action :authorize_read_govern_policy!, only: [:index, :show]
      before_action :authorize_create_govern_policy!, only: [:new]
      before_action :authorize_update_govern_policy!, only: [:edit]

      feature_category :security_policy_management
      urgency :low, [:index, :show, :new, :edit]

      def index
        render :index, locals: { group: group }
      end

      def show
        policy_id = params.permit(:id)[:id]

        render :show, locals: { group: group, policy_id: policy_id }
      end

      def new
        render :new, locals: { group: group }
      end

      def edit
        policy_id = params.permit(:id)[:id]

        render :edit, locals: { group: group, policy_id: policy_id }
      end

      private

      def container
        group
      end

      def ensure_policy_store_experiment_active!
        render_404 unless group.policy_store_experiment_active?
      end

      def authorize_read_govern_policy!
        render_404 unless can?(current_user, :read_govern_policy, group)
      end

      # new creates a policy and edit updates one, so each requires its matching ability.
      def authorize_create_govern_policy!
        render_404 unless can?(current_user, :create_govern_policy, group)
      end

      def authorize_update_govern_policy!
        render_404 unless can?(current_user, :update_govern_policy, group)
      end
    end
  end
end

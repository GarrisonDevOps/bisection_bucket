# frozen_string_literal: true

module Organizations
  module Security
    # Organization-scoped entry point for the experimental Policy Store. Mirrors the
    # group-level Groups::Security::PolicyStoreController so the experiment has an
    # organization home as Organizations matures, while the group controller remains
    # a fallback. index renders the list, show the read-only policy details, and
    # new/edit the client-side editor.
    class PolicyStoreController < ::Organizations::ApplicationController
      feature_category :security_policy_management
      urgency :low

      before_action :ensure_policy_store_experiment_active!
      before_action :authorize_read_govern_policy!, only: [:index, :show]
      before_action :authorize_create_govern_policy!, only: [:new]
      before_action :authorize_update_govern_policy!, only: [:edit]

      def index; end

      def show
        @policy_id = params.permit(:id)[:id]
      end

      def new; end

      def edit
        @policy_id = params.permit(:id)[:id]
      end

      private

      def ensure_policy_store_experiment_active!
        render_404 unless organization&.policy_store_experiment_active?
      end

      def authorize_read_govern_policy!
        render_404 unless can?(current_user, :read_govern_policy, organization)
      end

      # new creates a policy and edit updates one, so each requires its matching ability.
      def authorize_create_govern_policy!
        render_404 unless can?(current_user, :create_govern_policy, organization)
      end

      def authorize_update_govern_policy!
        render_404 unless can?(current_user, :update_govern_policy, organization)
      end
    end
  end
end

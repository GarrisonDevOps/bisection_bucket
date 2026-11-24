# frozen_string_literal: true

module Admin
  module Organizations
    class HooksController < Admin::Organizations::ApplicationController
      include ::WebHooks::HookActions
      include ::WebHooks::SystemHooksAvailability

      # rubocop:disable Rails/LexicallyScopedActionFilter -- actions are defined in WebHooks::HookActions
      before_action :check_feature_flag!
      before_action :check_default_organization!
      before_action :authorize_read_webhook!, only: :index
      before_action :authorize_create_webhook!, only: :create
      before_action :authorize_update_webhook!, only: [:edit, :update]
      before_action :authorize_delete_webhook!, only: :destroy
      before_action :authorize_test_webhook!, only: :test
      before_action :check_create_rate_limit!, only: :create
      # rubocop:enable Rails/LexicallyScopedActionFilter
      before_action :check_test_rate_limit!, only: :test
      before_action :set_organization

      urgency :low, [:test]

      def test
        result = TestHooks::SystemService.new(hook, current_user, params.permit(:trigger)[:trigger]).execute

        set_hook_execution_notice(result)

        redirect_back_or_default(default: { action: :index })
      end

      private

      def relation
        ::Current.organization.system_hooks
      end

      def hook_organization
        ::Current.organization
      end

      def hook
        @hook ||= relation.find(params.permit(:id)[:id])
      end

      def trigger_values
        SystemHook.triggers.values
      end

      def check_feature_flag!
        render_404 unless ::Feature.enabled?(:org_admin_hooks, ::Current.organization)
      end

      # Default org hooks are instance hooks and should be managed at /admin/hooks
      def check_default_organization!
        render_404 if ::Current.organization.default?
      end

      def authorize_read_webhook!
        access_denied! unless can?(current_user, :read_webhook, ::Current.organization)
      end

      def authorize_create_webhook!
        access_denied! unless can?(current_user, :create_webhook, ::Current.organization)
      end

      def authorize_update_webhook!
        access_denied! unless can?(current_user, :update_webhook, hook)
      end

      def authorize_delete_webhook!
        access_denied! unless can?(current_user, :delete_webhook, hook)
      end

      def authorize_test_webhook!
        access_denied! unless can?(current_user, :test_webhook, hook)
      end

      # Organization admins have no REST API for system hooks, so the API-side
      # limit never covers them.
      def check_create_rate_limit!
        check_rate_limit!(:system_hooks_create, scope: { user: current_user }, redirect_back: true)
      end

      def check_test_rate_limit!
        check_rate_limit!(:web_hook_test, scope: { organization: ::Current.organization, user: current_user })
      end

      def set_organization
        @organization = ::Current.organization
      end
    end
  end
end

# frozen_string_literal: true

module Admin
  module Organizations
    class HookLogsController < Admin::Organizations::ApplicationController
      include ::WebHooks::HookLogActions
      include ::WebHooks::SystemHooksAvailability

      before_action :check_feature_flag!
      before_action :check_default_organization!
      before_action :set_organization

      private

      def hook
        @hook ||= relation.find(params.permit(:hook_id)[:hook_id])
      end

      def relation
        ::Current.organization.system_hooks
      end

      def hook_log_container
        ::Current.organization
      end

      def after_retry_redirect_path
        edit_organization_admin_settings_hook_path(@organization, hook)
      end

      def check_feature_flag!
        render_404 unless ::Feature.enabled?(:org_admin_hooks, ::Current.organization)
      end

      # Default org hooks are instance hooks and should be managed at /admin/hooks
      def check_default_organization!
        render_404 if ::Current.organization.default?
      end

      def set_organization
        @organization = ::Current.organization
      end
    end
  end
end

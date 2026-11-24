# frozen_string_literal: true

module EE
  module ApplicationController
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    prepended do
      include ::Onboarding::Redirect
    end

    override :after_sign_out_path_for
    def after_sign_out_path_for(resource)
      if ::Gitlab::Geo.secondary?
        ::Gitlab::Geo.primary_node.oauth_logout_url(@geo_logout_state)
      else
        super
      end
    end

    private

    override :log_impersonation_event
    def log_impersonation_event
      super

      log_audit_event
    end

    def log_audit_event
      ::AuditEvents::UserImpersonationEventCreateWorker.perform_async(impersonator.id, current_user.id, request.remote_ip, 'stopped', DateTime.current)
    end
  end
end

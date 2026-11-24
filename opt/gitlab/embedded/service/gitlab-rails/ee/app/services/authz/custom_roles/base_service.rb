# frozen_string_literal: true

module Authz
  module CustomRoles
    class BaseService
      include Gitlab::Allowable
      include Gitlab::InternalEventsTracking

      def initialize(current_user, params = {})
        @current_user = current_user
        @params = params
      end

      private

      attr_reader :current_user, :params, :role

      def authorized_error
        ::ServiceResponse.error(message: _('Operation not allowed'), reason: :unauthorized)
      end

      def log_audit_event(action:)
        audit_context = {
          author: current_user,
          target: role,
          target_details: {
            name: role.name,
            description: role.description,
            abilities: role.enabled_permissions.keys.sort.join(', ')
          },
          **audit_event_attributes(action)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def audit_event_attributes(action)
        if role.admin_related_role?
          {
            name: "custom_admin_role_#{action}",
            scope: Gitlab::Audit::InstanceScope.new,
            message: "Custom admin role was #{action}"
          }
        else
          {
            name: "member_role_#{action}",
            scope: namespace || Gitlab::Audit::InstanceScope.new,
            message: "Member role was #{action}"
          }
        end
      end

      def collect_metrics
        track_internal_event(
          event_name,
          project: nil,
          namespace: namespace,
          user: current_user
        )
      end

      def namespace
        params[:namespace] || role.try(:namespace)
      end

      def success
        ::ServiceResponse.success(payload: role)
      end

      def error(message: role.errors.full_messages.join(', '))
        ::ServiceResponse.error(message: message,
          payload: safe_reset(role))
      end

      def safe_reset(model)
        model.reset
      rescue ActiveRecord::RecordNotFound
        nil
      end
    end
  end
end

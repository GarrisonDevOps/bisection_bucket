# frozen_string_literal: true

module Authz
  module AdminRoles
    class DeleteService < ::Authz::CustomRoles::BaseService
      def execute(role)
        @role = role

        return authorized_error unless allowed?

        if role.destroy
          log_audit_event(action: :deleted)
          collect_metrics

          success
        else
          error
        end
      end

      private

      def allowed?
        can?(current_user, :delete_admin_role, role)
      end

      def event_name
        'delete_admin_custom_role'
      end
    end
  end
end

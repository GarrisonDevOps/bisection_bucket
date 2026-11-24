# frozen_string_literal: true

module Authz
  module AdminRoles
    class UpdateService < ::Authz::CustomRoles::BaseService
      def execute(role)
        @role = role

        return authorized_error unless allowed?

        update_role
      end

      private

      def update_role
        role.assign_attributes(params.slice(:name, :description,
          *Gitlab::CustomRoles::Definition.admin.keys))

        if role.save
          log_audit_event(action: :updated)
          collect_metrics

          success
        else
          error
        end
      end

      def allowed?
        can?(current_user, :update_admin_role, role)
      end

      def event_name
        'update_admin_custom_role'
      end
    end
  end
end

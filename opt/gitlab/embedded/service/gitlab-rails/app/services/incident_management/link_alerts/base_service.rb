# frozen_string_literal: true

module IncidentManagement
  module LinkAlerts
    class BaseService < ::BaseProjectService
      private

      attr_reader :incident

      def allowed?
        Ability.allowed?(current_user, :admin_issue, incident)
      end

      def success
        ServiceResponse.success(payload: { incident: incident })
      end

      def error(message)
        ServiceResponse.error(message: message)
      end

      def error_no_permissions
        error(_('You have insufficient permissions to manage alerts for this project'))
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Namespaces
    module RestoreBaseService
      extend ::Gitlab::Utils::Override

      private

      override :log_event
      def log_event
        super

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def audit_context
        {
          name: "#{resource_name}_restored",
          author: current_user,
          scope: resource,
          target: resource,
          message: "#{resource_name.titleize} restored"
        }
      end
    end
  end
end

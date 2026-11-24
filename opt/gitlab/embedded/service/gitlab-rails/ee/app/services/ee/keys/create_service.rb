# frozen_string_literal: true

module EE
  module Keys
    module CreateService
      def execute
        super.tap do |key|
          log_audit_event(key)
        end
      end

      def log_audit_event(key)
        audit_context = {
          name: 'add_ssh_key',
          author: current_user,
          scope: user&.enterprise_group.presence || user,
          target: key,
          message: 'Added SSH key'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

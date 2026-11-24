# frozen_string_literal: true

module EE
  module Namespaces
    module Groups
      module UnarchiveService
        extend ::Gitlab::Utils::Override

        private

        override :after_unarchive
        def after_unarchive
          super

          log_audit_event
        end

        def log_audit_event
          audit_context = {
            name: 'group_unarchived',
            author: current_user,
            target: group,
            scope: group,
            message: 'Group unarchived'
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end

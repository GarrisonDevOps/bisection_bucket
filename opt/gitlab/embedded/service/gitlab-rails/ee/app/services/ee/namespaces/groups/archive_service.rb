# frozen_string_literal: true

module EE
  module Namespaces
    module Groups
      module ArchiveService
        extend ::Gitlab::Utils::Override

        private

        override :after_archive
        def after_archive
          super

          log_audit_event
        end

        def log_audit_event
          audit_context = {
            name: 'group_archived',
            author: current_user,
            target: group,
            scope: group,
            message: 'Group archived'
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end

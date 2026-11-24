# frozen_string_literal: true

module EE
  module Pages
    module Domains
      module BaseService
        extend ::Gitlab::Utils::Override

        private

        override :log_audit_event
        def log_audit_event(domain, action)
          audit_context = {
            name: "pages_domain_#{action}",
            author: current_user,
            scope: project,
            target: project,
            target_details: domain.domain,
            message: "#{action.humanize} pages domain #{domain.domain}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end

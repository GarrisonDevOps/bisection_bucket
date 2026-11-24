# frozen_string_literal: true

module Users
  module Abuse
    module NamespaceBans
      class BaseService < ::BaseService
        private

        def log_audit_event(user, namespace)
          audit_context = {
            name: event_name,
            author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: namespace,
            target: user,
            target_details: user.username,
            message: event_message
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end

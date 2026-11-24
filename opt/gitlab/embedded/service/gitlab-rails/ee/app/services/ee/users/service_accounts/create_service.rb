# frozen_string_literal: true

module EE
  module Users
    module ServiceAccounts
      module CreateService
        extend ::Gitlab::Utils::Override

        private

        override :after_successful_creation_hook
        def after_successful_creation_hook(user)
          log_service_account_audit_event(user)
        end

        def audit_scope(user)
          user
        end

        def log_service_account_audit_event(user)
          ::Gitlab::Audit::Auditor.audit({
            name: "service_account_created",
            author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: audit_scope(user),
            target: user,
            target_details: user.username,
            message: "Created service account #{user.username}"
          })
        end
      end
    end
  end
end

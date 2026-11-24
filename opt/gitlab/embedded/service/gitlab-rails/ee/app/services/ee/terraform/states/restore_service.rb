# frozen_string_literal: true

module EE
  module Terraform
    module States
      module RestoreService
        extend ::Gitlab::Utils::Override

        private

        override :log_event
        def log_event
          super
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        def audit_context
          {
            name: 'terraform_state_restored',
            author: current_user,
            scope: state.project,
            target: state,
            message: 'Terraform state restored'
          }
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Labels
    module CreateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(target_params)
        label = super

        audit_creation(label, target_params) if label.persisted? && current_user.present?

        label
      end

      private

      def audit_creation(label, target_params)
        scope = target_params[:project] || target_params[:group]
        return unless scope

        audit_context = {
          name: 'label_created',
          author: current_user,
          scope: scope,
          target: label,
          message: "Created label #{label.title}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

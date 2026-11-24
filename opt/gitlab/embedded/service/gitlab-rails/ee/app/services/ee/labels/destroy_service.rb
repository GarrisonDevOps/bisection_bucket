# frozen_string_literal: true

module EE
  module Labels
    module DestroyService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        scope = label.try(:parent_container) # must be captured before super destroys the record
        label = super

        audit_deletion(label, scope) if label.destroyed? && current_user.present?

        label
      end

      private

      def audit_deletion(label, scope)
        return unless scope

        audit_context = {
          name: 'label_deleted',
          author: current_user,
          scope: scope,
          target: label,
          message: "Deleted label #{label.title}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

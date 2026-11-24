# frozen_string_literal: true

module EE
  module Labels
    module UpdateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute(label)
        updated_label = super

        if updated_label.valid? && updated_label.saved_changes.present? && current_user.present?
          audit_update(updated_label)
        end

        updated_label
      end

      private

      def audit_update(label)
        scope = label.try(:parent_container)
        return unless scope

        if label.saved_changes.key?('title')
          old_title, new_title = label.saved_changes['title']
          message = "Changed label title from #{old_title} to #{new_title}"
        else
          message = "Updated label #{label.title}"
        end

        audit_context = {
          name: 'label_updated',
          author: current_user,
          scope: scope,
          target: label,
          message: message,
          additional_details: { changed_attributes: label.saved_changes.keys & %w[title description color archived
            lock_on_merge] }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

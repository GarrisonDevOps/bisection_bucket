# frozen_string_literal: true

module EE
  module WebHooks
    module UpdateService
      extend ::Gitlab::Utils::Override
      include ::WebHooks::AuditHelpers

      # attr_encrypted re-encrypts with a new IV on every assignment, so compare decrypted values.
      ENCRYPTED_ATTRIBUTES = %w[token url url_variables custom_headers].freeze

      IGNORED_ATTRIBUTES = %w[updated_at].freeze

      override :execute
      def execute(hook, hook_params)
        before = snapshot_encrypted_attributes(hook)

        result = super

        log_audit_event(hook, before) if result.success?

        result
      end

      private

      def log_audit_event(hook, encrypted_attributes_before)
        changed_attributes = normalized_changed_attributes(hook, encrypted_attributes_before)
        return if changed_attributes.empty?

        audit_context = {
          name: "webhook_updated",
          author: current_user,
          scope: hook_audit_scope(hook),
          target: hook,
          message: "Updated #{hook.model_name.human.downcase}",
          target_details: "Hook #{hook.id}",
          additional_details: hook_audit_details(hook).merge(changed_attributes: changed_attributes)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      # Attribute names only. Values are never recorded, since tokens, URL
      # credentials, URL variables and custom headers are secrets.
      def normalized_changed_attributes(hook, encrypted_attributes_before)
        # Blank-equivalent transitions (nil <-> "") are not real changes: the edit form
        # submits "" for fields that are stored as nil.
        plain_changes = hook.previous_changes.filter_map do |key, (old_value, new_value)|
          next if key.start_with?('encrypted_') || IGNORED_ATTRIBUTES.include?(key)
          next if old_value.presence == new_value.presence

          key
        end

        encrypted_changes = ENCRYPTED_ATTRIBUTES.select do |name|
          hook.public_send(name).presence != encrypted_attributes_before[name].presence # rubocop:disable GitlabSecurity/PublicSend -- fixed allowlist of attribute names
        end

        (plain_changes + encrypted_changes).uniq.sort
      end

      def snapshot_encrypted_attributes(hook)
        ENCRYPTED_ATTRIBUTES.index_with do |name|
          hook.public_send(name) # rubocop:disable GitlabSecurity/PublicSend -- fixed allowlist of attribute names
        end
      end
    end
  end
end

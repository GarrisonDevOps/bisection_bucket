# frozen_string_literal: true

module Ai
  module DuoSettings
    # Clears an admin-locked `duo_availability` override from a namespace.
    #
    # Resetting `duo_features_enabled` to nil lets the existing cascading
    # reader re-resolve the value from the parent group or the instance on the
    # next read. `lock_duo_features_enabled` is NOT NULL, so it is unlocked by
    # writing `false` rather than nil; a lock is inherently boolean.
    #
    # The lock is cleared before nilling `duo_features_enabled` because the
    # cascading `lock_#{attr}=` writer copies the resolved ancestor value into
    # the column whenever it is nil, which would freeze the value and defeat
    # re-resolution.
    class ClearNamespaceOverrideService
      def initialize(namespace:, current_user:)
        @namespace = namespace
        @current_user = current_user
      end

      def execute
        unless Ability.allowed?(current_user, :lock_namespace_duo_feature, namespace)
          return ServiceResponse.error(
            message: _('You are not authorized to clear the GitLab Duo availability override.'),
            reason: :forbidden
          )
        end

        previous_availability = namespace_setting.duo_availability

        namespace_setting.lock_duo_features_enabled = false
        namespace_setting.duo_features_enabled = nil
        namespace_setting.admin_locked_duo_features_enabled = false
        namespace_setting.save!

        # SetNamespaceOverrideService(clear_descendants: true) invokes this
        # service inside its own transaction; auditing inline would record
        # events for clears that a later rollback reverts. Deferring to
        # after-commit drops the audit on rollback, and runs it immediately
        # when no transaction is open (the standalone case).
        ActiveRecord.after_all_transactions_commit do
          audit_override_cleared(previous_availability)
          sync_amazon_q_integration
        end

        ServiceResponse.success(payload: { namespace_setting: namespace_setting })
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.join(', '))
      end

      private

      attr_reader :namespace, :current_user

      def namespace_setting
        @namespace_setting ||= namespace.namespace_settings
      end

      # A reloaded group: when SetNamespaceOverrideService clears descendants inside its transaction, this
      # setting's cascading memos were filled before the parent lock existed and would resolve the old state.
      def sync_amazon_q_integration
        response = ::Ai::AmazonQ::SyncGroupIntegrationService.new(namespace.reset).execute
        return unless response.error?

        Gitlab::AppLogger.warn(message: 'Amazon Q integration sync failed', group_id: namespace.id,
          error: response.message)
      end

      def audit_override_cleared(previous_availability)
        audit_context = {
          name: 'admin_override_cleared_for_namespace_duo_availability',
          author: current_user,
          scope: namespace,
          target: namespace,
          message: "Admin cleared duo_availability override (was '#{previous_availability}') " \
            "for namespace '#{namespace.full_path}'"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

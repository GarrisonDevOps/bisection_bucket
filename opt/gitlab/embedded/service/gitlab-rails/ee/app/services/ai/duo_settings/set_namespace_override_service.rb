# frozen_string_literal: true

module Ai
  module DuoSettings
    # Sets an admin-locked `duo_availability` override on a namespace.
    #
    # The admin writes through to the existing
    # (duo_features_enabled, lock_duo_features_enabled) pair so the existing
    # cascading-settings machinery propagates the value to subgroups and
    # projects, and additionally flags the row as admin-locked so the
    # owner-side params allowlist keeps owners from reverting it.
    class SetNamespaceOverrideService
      AVAILABILITY_VALUES = ::EE::NamespaceSetting::DUO_AVAILABILITY_VALUES
      LOCKING_VALUES = %w[always_on never_on].freeze

      def initialize(namespace:, current_user:, availability:, clear_descendants: false)
        @namespace = namespace
        @current_user = current_user
        @availability = availability.to_s
        @clear_descendants = clear_descendants
      end

      def execute
        authorization_error = authorize
        return authorization_error if authorization_error

        apply_override
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: e.record.errors.full_messages.join(', '))
      end

      private

      attr_reader :namespace, :current_user, :availability, :clear_descendants

      def authorize
        unless Ability.allowed?(current_user, :lock_namespace_duo_feature, namespace)
          return ServiceResponse.error(
            message: _('You are not authorized to set the GitLab Duo availability override.'),
            reason: :forbidden
          )
        end

        return if AVAILABILITY_VALUES.include?(availability)

        ServiceResponse.error(
          message: _('Invalid GitLab Duo availability value.'),
          reason: :invalid_availability
        )
      end

      def lock_key
        "duo_admin_availability_override:#{namespace.traversal_ids.first}"
      end

      def apply_override
        conflict = nil
        ::NamespaceSetting.transaction do
          # Serialize concurrent admin Duo-availability overrides within the same hierarchy.
          connection = ::NamespaceSetting.connection
          locked = connection.select_value(
            "SELECT pg_try_advisory_xact_lock(hashtext(#{connection.quote(lock_key)}))"
          )

          unless locked
            conflict = ServiceResponse.error(
              message: _('Another GitLab Duo availability override is in progress for this group. Please retry.'),
              reason: :conflict
            )
            raise ActiveRecord::Rollback
          end

          conflict = hierarchy_conflict
          raise ActiveRecord::Rollback if conflict

          # Delegate to NamespaceSetting#duo_availability= so admin-set values behave identically to
          # owner-set values, including the experiment-features side-effect for `never_on`. That side-effect
          # is one-way by design: transitioning away from `never_on` does not re-enable
          # `experiment_features_enabled`, it must be re-enabled explicitly.
          namespace_setting.duo_availability = availability
          namespace_setting.admin_locked_duo_features_enabled = true if availability.in?(LOCKING_VALUES)
          namespace_setting.save!
        end

        return conflict if conflict

        audit_override_set

        # The lock only writes namespace settings; the Amazon Q row and the Duo service-account memberships
        # would otherwise keep running until an Owner happened to save the group.
        sync_amazon_q_integration
        remove_duo_service_accounts if availability == 'never_on'

        ServiceResponse.success(payload: { namespace_setting: namespace_setting })
      end

      def sync_amazon_q_integration
        response = ::Ai::AmazonQ::SyncGroupIntegrationService.new(namespace).execute
        return unless response.error?

        Gitlab::AppLogger.warn(message: 'Amazon Q integration sync failed', group_id: namespace.id,
          error: response.message)
      end

      def remove_duo_service_accounts
        ai_settings = ::Ai::Setting.for_organization_read_only(namespace.organization)
        service_accounts = [
          (ai_settings.amazon_q_service_account_user if ::Ai::AmazonQ.connected?),
          (ai_settings.duo_workflow_service_account_user if ::Ai::DuoWorkflow.connected?)
        ].compact

        service_accounts.each do |service_account|
          ::Ai::ServiceAccountMemberRemoveService.new(current_user, namespace, service_account).execute
        end
      end

      def audit_override_set
        audit_context = {
          name: 'admin_override_set_for_namespace_duo_availability',
          author: current_user,
          scope: namespace,
          target: namespace,
          message: "Admin set duo_availability override to '#{availability}' for namespace '#{namespace.full_path}'"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      # Returns an error ServiceResponse when the override cannot be applied, or
      # nil when it is safe to proceed. Any descendant clearing happens here so
      # it is rolled back with the caller's transaction on failure.
      def hierarchy_conflict
        locked_ancestors = admin_locked_ancestors.to_a
        if locked_ancestors.any?
          # Surface the offending ancestor(s) so the UI can direct the admin to
          # clear the override there first (no `clearAncestors` shortcut by design).
          return ServiceResponse.error(
            message: _('A parent group already has an admin-locked GitLab Duo availability override.'),
            reason: :parent_admin_locked,
            payload: { namespaces: locked_ancestors.map(&:namespace) }
          )
        end

        locked_descendants = admin_locked_descendants.to_a
        return if locked_descendants.none?

        # A descendant admin lock would otherwise be left stale: setting a
        # locking value here makes the cascade clear the descendant's
        # `lock_duo_features_enabled`, so it silently resolves to this value
        # while still flagged admin-locked at its old value.
        unless clear_descendants
          # Surface the descendants that would be cleared so the UI can confirm
          # before retrying with `clear_descendants: true`.
          return ServiceResponse.error(
            message: _('A subgroup already has an admin-locked GitLab Duo availability override.'),
            reason: :descendant_admin_locked,
            payload: { namespaces: locked_descendants.map(&:namespace) }
          )
        end

        clear_error = clear_admin_locked_descendants(locked_descendants)
        ServiceResponse.error(message: clear_error) if clear_error
      end

      def namespace_setting
        @namespace_setting ||= namespace.namespace_settings
      end

      def admin_locked_ancestors
        ::NamespaceSetting.admin_locked_duo_features_for_ancestors_locked(namespace)
      end

      def admin_locked_descendants
        ::NamespaceSetting.admin_locked_duo_features_for_descendants_locked(namespace)
      end

      # Reuse ClearNamespaceOverrideService so the reset (and, later, its audit
      # event) stays identical to a standalone clear. Returns an error message
      # from the first failed clear, or nil when every descendant is cleared.
      def clear_admin_locked_descendants(settings)
        settings.each do |setting|
          response = ClearNamespaceOverrideService.new(
            namespace: setting.namespace,
            current_user: current_user
          ).execute

          return response.message if response.error?
        end

        nil
      end
    end
  end
end

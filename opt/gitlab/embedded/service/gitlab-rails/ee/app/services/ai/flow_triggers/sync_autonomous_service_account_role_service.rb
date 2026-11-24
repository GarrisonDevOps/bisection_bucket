# frozen_string_literal: true

module Ai
  module FlowTriggers
    # Brings an autonomous trigger's dedicated account back in step with the role
    # the flow's own account holds, so promoting or demoting the flow account
    # follows through instead of leaving the dedicated account on the role it was
    # provisioned with.
    #
    # Nothing else observes a change to the flow account's role, so callers
    # reconcile right before the dedicated account can act.
    class SyncAutonomousServiceAccountRoleService
      include ::Gitlab::Utils::StrongMemoize

      def initialize(project:, item_consumer:, service_account_id:, current_user: nil)
        @project = project
        @item_consumer = item_consumer
        @service_account_id = service_account_id
        @current_user = current_user
      end

      def execute
        member = service_account && project.member(service_account)

        return sa_role_unchanged(member) if access_level.nil?

        return sa_role_unchanged(member) if member && member.access_level == access_level
        return sa_role_unchanged(member) unless assignable_access_level?(member)

        # add_member re-adds an account that lost its membership and re-levels
        # one that kept it, so a single call covers both.
        relevelled = project.team.add_member(
          service_account, access_level,
          current_user: current_user, immediately_sync_authorizations: true
        ).presence

        return sa_role_changed if relevelled && relevelled.persisted? && relevelled.errors.empty?

        log_sync_failure(relevelled&.errors&.full_messages&.to_sentence.presence, member)
      end

      private

      attr_reader :project, :item_consumer, :service_account_id, :current_user

      # nil means there is no role to match, either because the flow has no
      # account or because that account is no longer a project member.
      def access_level
        item_consumer&.active_service_account_access_level(project)
      end
      strong_memoize_attr :access_level

      def assignable_access_level?(member)
        return false if access_level == ::Gitlab::Access::OWNER
        return false if ::Gitlab::Access.all_values.exclude?(access_level)
        return demotion_only?(member) if current_user.nil?
        return false unless project.can_assign_role?(current_user, access_level)

        member.nil? || project.can_assign_role?(current_user, member.access_level)
      end

      # A run has no actor, so it only ever reduces access. Granting more, or
      # re-adding a membership someone may have removed on purpose, is a
      # decision for a human: an edit makes it, capped by that editor's own role.
      #
      # Skipping leaves the run to fail on its own merits, or to be refused by
      # the eligibility check when there is no membership at all.
      def demotion_only?(member)
        return false if member.nil?

        ::Gitlab::Access.level_encompasses?(
          current_access_level: member.access_level,
          level_to_assign: access_level
        )
      end

      def log_sync_failure(message, member)
        message = message.presence || 'Failed to sync the service account role'

        ::Gitlab::AppLogger.error(
          message: 'Failed to sync the autonomous service account role',
          Labkit::Fields::GL_PROJECT_ID => project.id,
          service_account_id: service_account_id,
          error_message: message
        )

        ServiceResponse.error(
          message: message,
          reason: :validation_error,
          payload: role_payload(changed: false, current: member&.access_level)
        )
      end

      def sa_role_changed
        ServiceResponse.success(payload: role_payload(changed: true, current: access_level))
      end

      def sa_role_unchanged(member)
        ServiceResponse.success(payload: role_payload(changed: false, current: member&.access_level))
      end

      def role_payload(changed:, current:)
        effective = effective_access_level

        {
          changed: changed,
          access_level: access_level,
          current_access_level: current,
          effective_access_level: effective,
          excess_access: excess_access?(effective)
        }
      end

      # Effective access, not the member row, since group membership and shares grant access a re-level cannot
      # reach. A nil target means the flow holds nothing. Under-privilege is not caught: the run fails on its own.
      def excess_access?(effective)
        return false unless effective
        return true if access_level.nil?

        effective > access_level
      end

      def service_account
        ::User.find_by_id(service_account_id)
      end
      strong_memoize_attr :service_account

      def effective_access_level
        return unless service_account

        project.team.purge_member_access_cache_for_user_id(service_account_id)
        project.team.max_member_access(service_account_id).nonzero?
      end
    end
  end
end

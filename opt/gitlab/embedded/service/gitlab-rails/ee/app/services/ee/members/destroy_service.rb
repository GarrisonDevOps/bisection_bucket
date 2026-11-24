# frozen_string_literal: true

module EE
  module Members
    module DestroyService
      extend ::Gitlab::Utils::Override
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      def after_execute(member:, skip_saml_identity: false)
        super

        if system_event? && removed_due_to_expiry?(member)
          log_audit_event(member: member, author: nil, action: :expired)
        else
          log_audit_event(member: member, author: current_user, action: :destroy)
        end

        cleanup_group_identity(member) unless skip_saml_identity
        cleanup_oncall_rotations(member)
        cleanup_escalation_rules(member) if member.user
        reset_seats_usage_callouts(member)
        destroy_user_group_member_roles(member)
      end

      private

      def removed_due_to_expiry?(member)
        member.expired?
      end

      def system_event?
        current_user.blank?
      end

      def log_audit_event(member:, author:, action:)
        audit_context = {
          name: 'member_destroyed',
          author: author,
          scope: member.source,
          target: member.user || ::Gitlab::Audit::NullTarget.new,
          target_details: member.user ? member.user.name : 'Deleted User',
          additional_details: {
            remove: "user_access",
            as: member.human_access_labeled,
            member_id: member.id,
            member_role_id: member.member_role_id
          },
          ip_address: ip_address
        }

        audit_context[:additional_details][:duo_related] = true if duo_related_member?(member)

        if author.nil? || author.admin_bot?
          audit_context[:author] = ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)')
          audit_context[:additional_details][:system_event] = true
        end

        case action
        when :destroy
          audit_context[:message] = 'Membership destroyed'
          audit_context[:additional_details][:reason] = audit_reason if audit_reason.present?
        when :expired
          audit_context[:message] = "Membership expired on #{member.expires_at}"
          audit_context[:additional_details][:reason] = "access expired on #{member.expires_at}"
        end

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def duo_related_member?(member)
        member.user&.composite_ai_service_account?
      end

      def cleanup_group_identity(member)
        saml_provider = member.source.try(:saml_provider)

        return unless saml_provider

        saml_provider.identities.for_user(member.user).delete_all
      end

      def cleanup_oncall_rotations(member)
        user = member.user

        return unless user

        user_rotations = ::IncidentManagement::MemberOncallRotationsFinder.new(member).execute

        return unless user_rotations.present?

        ::IncidentManagement::OncallRotations::RemoveParticipantsService.new(
          user_rotations,
          user
        ).execute
      end

      def cleanup_escalation_rules(member)
        rules = ::IncidentManagement::EscalationRulesFinder.new(member: member, include_removed: true).execute

        ::IncidentManagement::EscalationRules::DestroyService.new(escalation_rules: rules, user: member.user).execute
      end

      override :enqueue_cleanup_jobs_once_per_hierarchy
      def enqueue_cleanup_jobs_once_per_hierarchy
        super

        enqueue_cleanup_add_on_seat_assignments
        enqueue_cleanup_group_protected_branch_rules
      end

      override :destroy_data_related_to_member
      def destroy_data_related_to_member
        super

        return unless member.user
        return unless member.source.licensed_feature_available?(:ai_features)

        ::Ai::UserAuthorizer.clear_group_with_ai_available_cache(member.user.id)
      end

      override :destroy_group_member_permission
      def destroy_group_member_permission
        if member.user&.service_account?
          :admin_service_account_member
        else
          super
        end
      end

      def enqueue_cleanup_add_on_seat_assignments
        namespace_id = member.source.root_ancestor.id
        member_user_id = member.user_id

        return unless gitlab_com_subscription?

        member.run_after_commit_or_now do
          ::GitlabSubscriptions::AddOnPurchases::CleanupUserAddOnAssignmentWorker.perform_async(
            namespace_id,
            member_user_id
          )
        end
      end

      def enqueue_cleanup_group_protected_branch_rules
        return unless member.source.is_a?(Group)

        member_source_id = member.source.id
        member_user_id = member.user_id

        member.run_after_commit_or_now do
          ::MembersDestroyer::CleanUpGroupProtectedBranchRulesWorker.perform_async(member_source_id, member_user_id)
        end
      end

      def reset_seats_usage_callouts(member)
        namespace_id = member.source.root_ancestor.id

        member.run_after_commit_or_now do
          ::Groups::ResetSeatCalloutsWorker.perform_async(namespace_id)
        end
      end

      def destroy_user_group_member_roles(member)
        user = member.user
        group = member.source

        return unless group.is_a?(Group)

        return unless member.member_role_id ||
          ::Authz::UserGroupMemberRole.for_user_in_group_and_shared_groups(user, group).exists? ||
          ::Authz::UserProjectMemberRole.for_user_shared_with_group(user, group).exists?

        ::Authz::UserGroupMemberRoles::DestroyForGroupWorker.perform_async(user.id, group.id)
      end
    end
  end
end

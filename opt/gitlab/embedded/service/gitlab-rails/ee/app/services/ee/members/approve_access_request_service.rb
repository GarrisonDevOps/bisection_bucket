# frozen_string_literal: true

module EE
  module Members
    module ApproveAccessRequestService
      extend ::Gitlab::Utils::Override
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      NoSeatError = Class.new(StandardError)
      MembershipLockedError = Class.new(StandardError)

      override :execute
      def execute(access_requester, skip_authorization: false, skip_log_audit_event: false)
        super
      rescue NoSeatError, MembershipLockedError => e
        error(e.message)
      end

      def after_execute(member:, skip_log_audit_event: false)
        super

        log_audit_event(member: member) unless skip_log_audit_event
      end

      private

      override :handle_request_acceptance
      def handle_request_acceptance(access_requester)
        if membership_locked?(access_requester.source, service_account: access_requester.user.service_account?)
          raise MembershipLockedError, _('Members cannot be added because membership is locked')
        end

        raise NoSeatError, _('No seat available') unless seat_available_for?(access_requester)

        super
      end

      def seat_available_for?(access_requester)
        root_group = access_requester.source.root_ancestor
        invites = Array.wrap(access_requester.user_id)
        access_level = access_requester.access_level

        !::GitlabSubscriptions::MemberManagement::BlockSeatOverages.block_seat_overages?(root_group) ||
          ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.seats_available_for?(root_group, invites,
            access_level, nil)
      end

      override :limit_to_guest_if_billable_promotion_restricted
      def limit_to_guest_if_billable_promotion_restricted(access_requester)
        return if current_user.present? && current_user.can_admin_all_resources?

        return unless member_promotion_management_enabled? &&
          ::User.non_billable_users_for_billable_management([access_requester.user.id]).present? &&
          promotion_management_required_for_role?(new_access_level: access_requester.access_level)

        access_requester.access_level = ::Gitlab::Access::GUEST
      end

      def log_audit_event(member:)
        audit_context = {
          name: 'member_created',
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: member.source,
          target: member.user || ::Gitlab::Audit::NullTarget.new,
          target_details: member.user&.name || 'Created User',
          message: 'Membership created',
          additional_details: {
            add: 'user_access',
            as: member.human_access_labeled,
            member_id: member.id
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module Members
    module CreateService
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils
      extend ::Gitlab::Utils::Override

      override :initialize
      def initialize(*args)
        super

        @queued_users = {}
        @added_member_ids_with_users = []
      end

      private

      attr_reader :queued_users
      attr_accessor :added_member_ids_with_users

      def create_params
        top_level_group = source.root_ancestor

        return super unless top_level_group.custom_roles_enabled?

        super.merge(member_role_id: params[:member_role_id])
      end

      override :cannot_assign_owner_responsibilities_to_member_in_project?
      def cannot_assign_owner_responsibilities_to_member_in_project?
        # The purpose of this check is
        # to allow member modification when called through an admin authorized
        # flow, where we might not have admin's current_user object available.
        return false if current_user.nil? && params[:skip_authorization]

        super
      end

      def validate_invitable!
        super

        check_membership_lock!
        check_quota!
        check_seats!
      end

      def check_quota!
        return unless invite_quota_exceeded?

        message = format(
          s_("AddMember|Invite limit of %{daily_invites} per day exceeded."),
          daily_invites: source.actual_limits.daily_invites
        )
        raise ::Members::CreateService::TooManyInvitesError, message
      end

      def check_membership_lock!
        return unless source.membership_locked?
        return unless source.membership_locked_for?(current_user, service_account: service_account_invites?)

        @membership_locked = true # rubocop:disable Gitlab/ModuleWithInstanceVariables
        raise ::Members::CreateService::MembershipLockedError,
          _('Members cannot be added because membership is locked')
      end

      def service_account_invites?
        # `invites` can hold email strings (invitations path), and `User.id_in` casts a
        # digit-leading email such as "42@example.com" to id 42. Require every entry to be a plain
        # numeric id so an email cannot borrow a service account's id to slip past the lock.
        return false unless invites.all? { |invite| invite.to_s.match?(/\A\d+\z/) }

        invited_users = ::User.id_in(invites)

        invited_users.size == invites.uniq.size && invited_users.all?(&:service_account?)
      end

      def check_seats!
        return unless ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.block_seat_overages?(source)

        return if ::GitlabSubscriptions::MemberManagement::BlockSeatOverages.seats_available_for?(source,
          invites, params[:access_level], params[:member_role_id])

        notify_owners(invites)

        messages = [
          s_('AddMember|There are not enough available seats to invite this many users.')
        ]

        unless Ability.allowed?(current_user, :change_seat_control, source.root_ancestor)
          messages << s_('AddMember|Ask a user with the Owner role to purchase more seats.')
        end

        raise ::Members::CreateService::SeatLimitExceededError, messages.join(" ")
      end

      def notify_owners(invites)
        root_namespace = source.root_ancestor

        return if root_namespace.owners.include?(current_user)

        invited_user_ids = invites.select { |i| i.to_i.to_s == i }

        return if invited_user_ids.empty?

        # rubocop:disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- Limit of 100 is defined in validate_invitable! method
        requested_member_list = ::User.id_in(invited_user_ids).pluck(:name)
        # rubocop:enable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord

        ::NotificationService.new.no_more_seats(
          root_namespace, root_namespace.owners, current_user, requested_member_list
        )
      end

      def invite_quota_exceeded?
        return if source.actual_limits.daily_invites == 0

        invite_count = ::Member.invite.created_today.in_hierarchy(source).count

        source.actual_limits.exceeded?(:daily_invites, invite_count + invites.count)
      end

      override :after_add_hooks
      def after_add_hooks
        super

        return unless execute_notification_worker?

        ::Namespaces::FreeUserCap::GroupOverLimitNotificationWorker
          .perform_async(source.id, added_member_ids_with_users)
      end

      def execute_notification_worker?
        ::Namespaces::FreeUserCap.dashboard_limit_enabled? &&
          source.is_a?(Group) && # only ever an invited group's members could affect this
          added_member_ids_with_users.any?
      end

      def after_execute(member:)
        super

        append_added_member_ids_with_users(member: member)
        log_audit_event(member: member)
        convert_invited_user_to_invite_onboarding(member: member)
        finish_onboarding_user(member: member)
      end

      def convert_invited_user_to_invite_onboarding(member:)
        # When a user is in onboarding, but have not finished onboarding and then are invited, we need
        # to then convert that user to be an invite registration.
        # By placing this logic here instead of the member creator classes, we avoid system actions like
        # adding user as the owner in Groups::CreateService that occurs during user registration and would
        # incorrectly change the registration_type to an invite.
        # All application UI or API cases should travel through this code on user invites.
        return unless member.user.present?

        ::Onboarding::StatusConvertToInviteService.new(member.user).execute
      end

      def finish_onboarding_user(member:)
        # We perform this at the invite level since it is a more targeted way to finish onboarding.
        # This should always be coupled with convert_invited_user_to_invite_onboarding as
        # we have to still be in onboarding in order for convert_invited_user_to_invite_onboarding
        # to work properly.
        return unless finished_welcome_step?(member: member)

        ::Onboarding::FinishService.new(member.user).execute
      end

      def finished_welcome_step?(member:)
        member.user&.onboarding_status_role.present?
      end

      def append_added_member_ids_with_users(member:)
        return unless ::Namespaces::FreeUserCap.dashboard_limit_enabled?
        return unless new_and_attached_to_user?(member: member)

        added_member_ids_with_users << member.id
      end

      def new_and_attached_to_user?(member:)
        # Only members attached to users can possibly affect the user count.
        # If the member was merely updated, they won't affect a change to the user count.
        member.user_id && member.previously_new_record?
      end

      def log_audit_event(member:)
        audit_context = {
          name: 'member_created',
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: member.source,
          target: member.user || ::Gitlab::Audit::NullTarget.new,
          target_details: member.user&.name || 'Created Member',
          message: 'Membership created',
          additional_details: {
            add: 'user_access',
            as: member.human_access_labeled,
            member_id: member.id,
            member_role_id: member.member_role_id
          }
        }

        audit_context[:additional_details][:expires_at] = member.expires_at

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      override :process_result
      def process_result(member)
        if member.errors.added?(:base, :queued)
          queued_users[member.user.username] = member.errors.delete(:base, :queued).first
        end

        super(member)
      end

      override :result
      def result(pass_back = {})
        pass_back[:queued_users] = queued_users if queued_users.any?

        super(pass_back)
      end

      override :publish_event!
      def publish_event!
        super

        return unless should_publish_admin_events?

        members.each do |member|
          next unless member_eligible_for_admin_event?(member)

          ::Gitlab::EventStore.publish(
            ::Members::MembershipModifiedByAdminEvent.new(data: {
              member_user_id: member.user_id
            })
          )
        end
      end

      def should_publish_admin_events?
        member_promotion_management_enabled? &&
          current_user&.can_admin_all_resources? &&
          at_least_one_member_created?
      end
    end
  end
end

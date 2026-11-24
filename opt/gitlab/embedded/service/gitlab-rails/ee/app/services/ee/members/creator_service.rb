# frozen_string_literal: true

module EE
  module Members
    module CreatorService
      extend ::Gitlab::Utils::Override
      extend ActiveSupport::Concern

      private

      class_methods do
        extend ::Gitlab::Utils::Override

        def parsed_args(args)
          super.merge(member_role_id: args[:member_role_id])
        end

        override :build_members
        def build_members(emails, users, common_arguments)
          current_user = common_arguments[:current_user]

          return super unless current_user.present?
          return super if current_user.can_admin_all_resources?
          return super unless users.present? || emails.present?

          params = common_arguments.merge(
            access_level: parsed_access_level(common_arguments[:access_level]),
            emails: emails,
            users: users
          )

          response = ::GitlabSubscriptions::MemberManagement::QueueNonBillableToBillableService.new(
            current_user: current_user,
            params: params
          ).execute

          if response.error?
            errored_members = response.payload[:non_billable_to_billable_members]
            return errored_members
          end

          billable_users = response.payload[:billable_users]
          emails_not_queued_for_approval = response.payload[:emails_not_queued_for_approval]
          members = response.payload[:non_billable_to_billable_members]
          members += super(emails_not_queued_for_approval, billable_users, common_arguments)

          members
        end
      end

      override :member_attributes
      def member_attributes
        attributes = super.merge(ldap: ldap)

        top_level_group = source.root_ancestor

        return attributes unless top_level_group.custom_roles_enabled?

        attributes.merge(member_role_id: args[:member_role_id])
      end

      override :commit_member
      def commit_member
        if security_bot_and_member_of_other_project?
          member.errors.add(:base, _('security policy bot users cannot be added to other projects'))
        else
          super
        end
      end

      def security_bot_and_member_of_other_project?
        return false unless member.user&.security_policy_bot?

        ::Member.exists?(user_id: member.user.id) # rubocop:disable CodeReuse/ActiveRecord
      end
    end
  end
end

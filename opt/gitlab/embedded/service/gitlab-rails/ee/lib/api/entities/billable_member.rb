# frozen_string_literal: true

module API
  module Entities
    class BillableMember < ::API::Entities::UserBasic
      expose :public_email, as: :email, documentation: { type: 'String' }
      expose :email, documentation: { type: 'String' }, if: ->(user, options) do
        options[:current_user]&.can_admin_all_resources? ||
          user.can_read_email_enterprise_user?(options[:current_user], group: options[:group])
      end
      expose :last_activity_on, documentation: { type: 'Date' }
      expose :membership_type, documentation: { type: 'String' }
      expose :removable, documentation: { type: 'Boolean' }
      expose :created_at, documentation: { type: 'DateTime' }
      expose :last_owner?, as: :is_last_owner, documentation: { type: 'Boolean' }
      expose :current_sign_in_at, as: :last_login_at, documentation: { type: 'DateTime' }

      private

      def membership_type
        return 'group_member'   if user_in_array?(:group_member_user_ids)
        return 'project_member' if user_in_array?(:project_member_user_ids)
        return 'group_invite'   if user_in_array?(:shared_group_user_ids)

        'project_invite' if user_in_array?(:shared_project_user_ids)
      end

      def last_owner?
        options[:group].last_owner_in_list?(object, options.fetch(:owners, []))
      end

      def removable
        user_in_array?(:group_member_user_ids) || user_in_array?(:project_member_user_ids)
      end

      def user_in_array?(name)
        options.fetch(name, []).include?(object.id)
      end
    end
  end
end

# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class QueueNonBillableToBillableService < BaseService
      include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils
      include ::Gitlab::Utils::StrongMemoize

      def initialize(current_user:, params:)
        @current_user = current_user
        @params = params

        assign_users_members_emails_and_source
        source_namespace
      end

      def execute
        return nothing_to_queue unless promotion_management_required?

        # before we perform billable_role_change? ensure access_level and member_role_id have valid values
        sanitize_access_level_and_member_role_id
        return nothing_to_queue unless billable_role_change?

        non_billable_to_billable_users, billable_users = partition_non_billable_and_billable_users
        return nothing_to_queue unless non_billable_to_billable_users.present?

        response = queue_non_billable_to_billable_users_for_approval(non_billable_to_billable_users)
        queued_non_billable_to_billable_members = build_non_billable_to_billable_members_with_service_errors(
          non_billable_to_billable_users, response.error?
        )
        queued_member_approvals = response[:users_queued_for_approval]

        billable_members = billable_members(billable_users)

        emails_not_queued_for_approval = []
        unless emails.empty?
          non_billable_emails_downcased = non_billable_to_billable_users.map { |user| user.email.downcase }

          # Remove emails of queued members from emails list to ensure they don't get promoted
          emails_not_queued_for_approval = emails.reject do |email|
            non_billable_emails_downcased.include?(email.downcase)
          end
        end

        if response.error?
          return error(
            billable_users: billable_users,
            billable_members: billable_members,
            emails_not_queued_for_approval: emails_not_queued_for_approval,
            non_billable_to_billable_members: queued_non_billable_to_billable_members
          )
        end

        success(
          billable_users: billable_users,
          billable_members: billable_members,
          emails_not_queued_for_approval: emails_not_queued_for_approval,
          non_billable_to_billable_members: queued_non_billable_to_billable_members,
          queued_member_approvals: queued_member_approvals
        )
      end

      private

      attr_accessor :users, :members, :existing_members_hash, :params, :new_access_level,
        :source, :member_role_id, :emails, :users_by_emails_hash

      def source_namespace
        case source
        when ::Group then source
        when ::Project then source.project_namespace
        else
          raise ArgumentError, 'Invalid source. Source should be either Group or Project.'
        end
      end
      strong_memoize_attr :source_namespace

      def assign_users_members_emails_and_source
        @source = params[:source]
        @emails = params[:emails] || []
        @users_by_emails_hash = params[:users_by_emails] || {}

        if params[:users].present? || emails.present?
          # invite flow with users or emails passed, we should at least have users or emails
          @users = params[:users] || []
          @existing_members_hash = params[:existing_members] || {}
          @members = existing_members_hash.values

          # hash contains nil values for users not present in the system, removing them
          users_by_emails_hash.reject! { |_, value| value.nil? }
        elsif params[:members].present?
          # update flow with members passed
          @members = params[:members]
          @users = members.map(&:user)
          @existing_members_hash = members.index_by(&:user_id)
        else
          raise ArgumentError, 'Invalid argument. Either members or users or email should be passed.'
        end
      end

      def sanitized_params
        sanitized_params = params.slice(:expires_at, :member_role_id).to_h
        sanitized_params[:access_level] = new_access_level
        sanitized_params[:existing_members_hash] = existing_members_hash
        sanitized_params[:source_namespace] = source_namespace

        sanitized_params
      end

      def queue_non_billable_to_billable_users_for_approval(non_billable_to_billable_users)
        GitlabSubscriptions::MemberManagement::QueueMembersApprovalService
          .new(non_billable_to_billable_users, current_user, sanitized_params)
          .execute
      end

      def sanitize_access_level_and_member_role_id
        self.new_access_level = params[:access_level]

        unless custom_role_feature_enabled?
          params.delete(:member_role_id)
          return
        end

        member_role = MemberRole.find_by_id(params[:member_role_id])
        return unless member_role

        self.member_role_id = member_role.id
        self.new_access_level = member_role.base_access_level if new_access_level.nil?
      end

      def promotion_management_required?
        return false if current_user.can_admin_all_resources?

        member_promotion_management_enabled?
      end

      def billable_role_change?
        new_access_level.present? &&
          promotion_management_required_for_role?(
            new_access_level: new_access_level,
            member_role_id: member_role_id
          )
      end

      def custom_role_feature_enabled?
        ::License.feature_available?(:custom_roles)
      end

      def build_non_billable_to_billable_members_with_service_errors(non_billable_to_billable_users, error)
        # Build members with service errors to pass back to consumers
        # as we wont be updating/adding these members until Admin Approval
        non_billable_to_billable_users.map do |user|
          member = ::Members::StandardMemberBuilder.new(source, user, existing_members_hash).execute
          member.access_level = new_access_level
          member.member_role_id = member_role_id

          if error
            member.errors.add(:base, :invalid, message: _("Unable to send approval request to administrator."))
          else
            member.errors.add(:base, :queued, message: _("Request queued for administrator approval."))
          end

          member
        end
      end

      def partition_non_billable_and_billable_users
        all_users = users + users_by_emails_hash.values
        all_user_ids = all_users.map(&:id)

        non_billable_to_billable_users = GitlabSubscriptions::MemberManagement::SelfManaged::NonBillableUsersFinder
                               .new(current_user, all_user_ids).execute

        # since all_users will contain users added by email as well, we need to just return
        # users added by users list
        billable_users = users.select { |user| non_billable_to_billable_users.exclude?(user) }

        [non_billable_to_billable_users, billable_users]
      end

      def billable_members(billable_users)
        members.select { |member| billable_users.include?(member.user) }
      end

      def nothing_to_queue
        success(billable_users: users, billable_members: members, emails_not_queued_for_approval: emails)
      end

      def success(
        billable_users:, billable_members:, emails_not_queued_for_approval:,
        non_billable_to_billable_members: [], queued_member_approvals: []
      )
        ServiceResponse.success(payload: {
          billable_users: billable_users,
          billable_members: billable_members,
          non_billable_to_billable_members: non_billable_to_billable_members,
          emails_not_queued_for_approval: emails_not_queued_for_approval,
          queued_member_approvals: queued_member_approvals
        })
      end

      def error(billable_users:, billable_members:, emails_not_queued_for_approval:, non_billable_to_billable_members:)
        ServiceResponse.error(
          message: "Invalid record while enqueuing users for approval",
          payload: {
            users: users,
            members: members,
            billable_users: billable_users,
            billable_members: billable_members,
            emails_not_queued_for_approval: emails_not_queued_for_approval,
            non_billable_to_billable_members: non_billable_to_billable_members
          }.compact
        )
      end
    end
  end
end

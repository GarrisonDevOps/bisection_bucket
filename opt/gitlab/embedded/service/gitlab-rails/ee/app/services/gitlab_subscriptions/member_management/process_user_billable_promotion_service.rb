# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class ProcessUserBillablePromotionService < BaseService
      include GitlabSubscriptions::MemberManagement::PromotionManagementUtils

      def initialize(user, current_user, params)
        @current_user = current_user
        @user = user
        @status = params[:status]
        @skip_authorization = params[:skip_authorization] || false
        @failed_member_approvals = []
        @successful_promotion_count = 0
      end

      def execute
        return error('Unauthorized') unless authorized?

        case status
        when :denied
          deny_member_approvals
        when :approved
          apply_member_approvals
        else
          error("Invalid #{status}")
        end
      rescue ActiveRecord::ActiveRecordError => e
        Gitlab::AppLogger.error(message: "Failed to update member approval status to #{status}: #{e.message}")
        Gitlab::ErrorTracking.track_exception(e)
        error("Failed to update member approval status to #{status}")
      end

      private

      attr_reader :current_user, :user, :status, :skip_authorization
      attr_accessor :failed_member_approvals, :successful_promotion_count

      def authorized?
        return false unless member_promotion_management_enabled?

        (current_user.present? &&
          current_user.can_admin_all_resources?) || skip_authorization
      end

      def apply_member_approvals
        pending_approvals.find_each do |member_approval|
          response = process_member_approval(member_approval)

          if response[:status] == :error
            failed_member_approvals << member_approval
            Gitlab::AppLogger.error(message: "Failed to apply pending promotions: #{response[:message]}")
          else
            member_approval.update!(
              status: :approved,
              reviewed_by: current_user
            )
            self.successful_promotion_count += 1
          end
        end

        return error("Failed to apply promotions") if all_promotions_failed? && user_non_billable?

        approve_failed_member_approvals
        success_status = failed_member_approvals.present? ? :partial_success : :success

        success(success_status)
      end

      def process_member_approval(member_approval)
        source = member_approval.member_namespace.owner_entity
        params = member_approval_params(member_approval, source)

        ::Members::CreateService.new(current_user, params).execute
      end

      def pending_approvals
        ::GitlabSubscriptions::MemberManagement::MemberApproval.pending_member_approvals_for_user(user.id)
      end

      def all_promotions_failed?
        successful_promotion_count == 0 && failed_member_approvals.present?
      end

      def user_non_billable?
        ::User.non_billable_users_for_billable_management([user.id]).present?
      end

      def member_approval_params(member_approval, source)
        params = member_approval.metadata.symbolize_keys
        params.merge!(
          user_id: [user.id],
          source: source,
          access_level: member_approval.new_access_level,
          invite_source: self.class.name,
          skip_authorization: skip_authorization
        )
      end

      def deny_member_approvals
        pending_approvals.each_batch do |batch|
          batch.update_all(
            updated_at: Time.current,
            status: :denied,
            reviewed_by_id: current_user&.id
          )
        end

        success
      end

      def approve_failed_member_approvals
        failed_member_approvals.each do |member_approval|
          member_approval.update!(
            status: :approved,
            reviewed_by: current_user
          )
        end
      end

      def trigger_web_hook(action_status)
        payload = Gitlab::DataBuilder::MemberApprovalBuilder.build(
          event: status,
          reviewed_by: current_user,
          reviewed_at: Time.current,
          user: user,
          status: action_status,
          failed_approvals: failed_member_approvals
        )

        # A user belongs to exactly one organization, which is where the system hooks must run.
        organization = user.organization # rubocop:disable Gitlab/AvoidUserOrganization -- see comment above

        SystemHooksService.new.execute_hooks(payload, :member_approval_hooks, organization: organization)
      end

      def success(result = :success)
        trigger_web_hook(result)

        ServiceResponse.success(
          message: "Successfully processed request",
          payload: {
            result: result,
            user: user,
            status: status
          }
        )
      end

      def error(message)
        trigger_web_hook(:failed)

        ServiceResponse.error(
          message: message,
          payload: {
            result: :failed
          }
        )
      end
    end
  end
end

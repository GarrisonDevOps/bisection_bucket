# frozen_string_literal: true

module EE
  module Admin
    module UsersController
      extend ::ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      include SafeFormatHelper

      prepended do
        authorize! :read_admin_users, only: [:index, :show]

        before_action only: [:new, :edit, :index] do
          push_licensed_feature(:custom_roles)
        end

        before_action only: [:index] do
          push_frontend_ability(ability: :read_admin_role, user: current_user)
        end
      end

      def identity_verification_exemption
        if @user.add_identity_verification_exemption("set by #{current_user.username}")
          redirect_to [:admin, @user], notice: _('Added identity verification exemption.')
        else
          redirect_to [:admin, @user], alert: _('Something went wrong. Unable to add identity verification exemption.')
        end
      end

      def destroy_identity_verification_exemption
        if @user.remove_identity_verification_exemption
          redirect_to [:admin, @user], notice: _('Removed identity verification exemption.')
        else
          redirect_to [:admin, @user], alert: _('Something went wrong. Unable to remove identity verification exemption.')
        end
      end

      def reset_runners_minutes
        user

        ::Ci::Minutes::ResetUsageService.new(@user.namespace).execute
        redirect_to [:admin, @user], notice: _('User compute minutes were successfully reset.')
      end

      def card_match
        return render_404 unless ::Gitlab::Saas.feature_available?(:identity_verification)

        credit_card_validation = user.credit_card_validation

        if credit_card_validation.present?
          @similar_credit_card_validations = credit_card_validation.similar_records.page(pagination_params[:page]).per(100)
        else
          redirect_to [:admin, @user], notice: _('No credit card data for matching')
        end
      end

      def phone_match
        return render_404 unless ::Gitlab::Saas.feature_available?(:identity_verification)

        phone_number_validation = user.phone_number_validation

        if phone_number_validation.present?
          @similar_phone_number_validations = phone_number_validation.similar_records.page(pagination_params[:page]).per(100)
        else
          redirect_to [:admin, @user], notice: _('No phone number data for matching')
        end
      end

      private

      override :users_with_included_associations
      def users_with_included_associations(users)
        admin_role = extract_admin_roles? ? :admin_role : :member_role

        super.includes(:oncall_schedules, :escalation_policies, :user_highest_role, admin_role).preload(:elevated_members) # rubocop: disable CodeReuse/ActiveRecord -- preloads associations for the admin users list
      end

      override :partial_email_search?
      def partial_email_search?
        !::Gitlab::Saas.feature_available?(:disable_partial_email_search)
      end

      override :log_impersonation_event
      def log_impersonation_event
        super

        log_audit_event
      end

      override :unlock_user
      def unlock_user
        update_user do
          user.unlock_access!(unlocked_by: current_user)
        end
      end

      override :after_successful_create_hook
      def after_successful_create_hook(user)
        assign_admin_role(user)
      end

      override :after_successful_update_hook
      def after_successful_update_hook(user)
        assign_admin_role(user)
      end

      def assign_admin_role(user)
        update_assignment = user.admin? || # rubocop:disable Cop/UserAdmin -- Not current_user so no need to check if admin mode is enabled
          user_admin_role_params.key?(:admin_role_id)

        return unless update_assignment
        return unless ::License.feature_available?(:custom_roles)

        # If admin_role_id is in params but does not have a value or if
        # admin_role_id is not in params but updated user is an admin we set
        # member_role param to nil to instruct the service to remove the user's
        # current role assignment
        role_id = user_admin_role_params[:admin_role_id]
        role = role_id.present? ? MemberRole.find_by_id(role_id) : nil

        result = ::Users::MemberRoles::AssignService.new(current_user, { user: user, member_role: role }).execute

        @assign_admin_role_error = result.message if result.error?
      end

      override :after_successful_create_flash
      def after_successful_create_flash
        return super unless assign_admin_role_error

        { alert: assign_admin_role_error }
      end

      override :after_successful_update_flash
      def after_successful_update_flash
        return super unless assign_admin_role_error

        { alert: assign_admin_role_error }
      end

      def assign_admin_role_error
        return unless @assign_admin_role_error

        _("Failed to assign custom admin role. Try again or select a different role.")
      end

      def user_admin_role_params
        params.require(:user).permit(:admin_role_id)
      end

      def log_audit_event
        ::AuditEvents::UserImpersonationEventCreateWorker.perform_async(current_user.id, user.id, request.remote_ip, 'started', DateTime.current)
      end

      def allowed_user_params
        super + [
          namespace_attributes: [
            :id,
            :shared_runners_minutes_limit,
            { gitlab_subscription_attributes: [:hosted_plan_name_uid] }
          ],
          custom_attributes_attributes: [:id, :value]
        ]
      end

      def filter_users
        return super unless admin_role_param

        assignments = extract_admin_roles? ? ::Authz::UserAdminRole : ::Users::UserMemberRole

        assignments.filter_users(super, admin_role_param)
      end

      def extract_admin_roles?
        ::Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
      end

      def admin_role_param
        params.permit(:admin_role_id)[:admin_role_id]
      end
    end
  end
end

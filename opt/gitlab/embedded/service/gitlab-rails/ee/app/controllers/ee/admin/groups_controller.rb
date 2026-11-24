# frozen_string_literal: true

module EE
  module Admin
    module GroupsController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        feature_category :continuous_integration, [:reset_runners_minutes]

        authorize! :read_admin_groups, only: %i[index show]

        before_action do
          push_saas_feature(:gitlab_com_subscriptions)
        end

        before_action only: [:index] do
          push_saas_feature(:group_project_permanent_deletion_confirmation)
          push_dedicated_feature(:group_project_permanent_deletion_confirmation)
        end
      end

      def reset_runners_minutes
        group

        ::Ci::Minutes::ResetUsageService.new(@group).execute
        redirect_to [:admin, @group], notice: _('Group compute minutes were successfully reset.')
      end

      private

      def allowed_group_params
        super + [
          :repository_size_limit,
          :shared_runners_minutes_limit,
          :pipeline_execution_policies_per_configuration_limit,
          :scan_execution_policies_per_configuration_limit,
          :approval_policies_per_configuration_limit,
          :vulnerability_management_policies_per_configuration_limit,
          :dependency_firewall_policies_per_configuration_limit,
          { gitlab_subscription_attributes: [:hosted_plan_name_uid] }
        ]
      end

      override :group_members
      def group_members
        return @group.all_group_members if @group.minimal_access_role_allowed?

        @group.members
      end

      def groups
        super.with_deletion_schedule
      end
    end
  end
end

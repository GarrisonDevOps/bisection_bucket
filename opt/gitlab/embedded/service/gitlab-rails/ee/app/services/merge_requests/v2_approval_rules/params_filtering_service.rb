# frozen_string_literal: true

module MergeRequests
  module V2ApprovalRules
    class ParamsFilteringService < ApprovalRules::ParamsFilteringService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        params.delete(:v2_approval_rules_attributes) unless Ability.allowed?(current_user, :update_approvers, target)

        filter_non_user_defined_rules if updating?
        params.delete(:reset_approval_rules_to_defaults) unless updating?

        return params unless params.key?(:v2_approval_rules_attributes)

        params[:v2_approval_rules_attributes]&.each do |v2_rule_attributes|
          handle_rule(v2_rule_attributes)
        end

        params
      end

      private

      # v2 attributes use :approver_group_ids/:approver_user_ids instead of :group_ids/:user_ids,
      # and live under :v2_approval_rules_attributes rather than :approval_rules_attributes.
      override :batch_load_visible_user_and_group_ids
      def batch_load_visible_user_and_group_ids
        return unless params.key?(:v2_approval_rules_attributes)

        # rubocop: disable CodeReuse/ActiveRecord -- replicate ancestor v1 filter service structure
        # rubocop: disable Database/AvoidUsingPluckWithoutLimit: -- replicate ancestor v1 filter service structure
        @visible_group_ids = params[:v2_approval_rules_attributes].flat_map { |hash| hash[:approver_group_ids] }

        if @visible_group_ids.present?
          org = ::Organizations::Organization.find_by_id_with_isolation_record(project.organization_id)
          groups = filter_cross_organization_groups(::Group.id_in(@visible_group_ids), organization: org)
          @visible_group_ids = groups.accessible_to_user(current_user).pluck(:id)
        end

        @visible_user_ids = params[:v2_approval_rules_attributes].flat_map { |hash| hash[:approver_user_ids] }
        return unless @visible_user_ids.present?

        @visible_user_ids = project.members_among(::User.id_in(@visible_user_ids)).pluck(:id)
        # rubocop: enable CodeReuse/ActiveRecord
        # rubocop: enable Database/AvoidUsingPluckWithoutLimit
      end

      # v2 approval rules attributes do not currently support hidden groups, so they are not yet handled.
      # This is gap that should be handled to achieve parity with approvals_v1.
      override :handle_rule
      def handle_rule(rule_attributes)
        if rule_attributes.key?(:approver_group_ids)
          provided_group_ids = rule_attributes[:approver_group_ids].map(&:to_i)
          rule_attributes[:approver_group_ids] = provided_group_ids & visible_group_ids
        end

        if rule_attributes.key?(:approver_user_ids)
          provided_user_ids = rule_attributes[:approver_user_ids].map(&:to_i)
          rule_attributes[:approver_user_ids] = provided_user_ids & visible_user_ids
        end

        unless rule_attributes[:approver_group_ids].blank? &&
            rule_attributes[:approver_user_ids].blank? && rule_attributes[:name].blank?
          return
        end

        rule_attributes[:rule_type] = :any_approver
        rule_attributes[:name] = ApprovalRuleLike::ALL_MEMBERS
      end
    end
  end
end

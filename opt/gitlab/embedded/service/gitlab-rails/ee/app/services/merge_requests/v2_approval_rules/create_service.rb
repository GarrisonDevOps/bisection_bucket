# frozen_string_literal: true

module MergeRequests
  module V2ApprovalRules
    class CreateService < BaseService
      private

      def action
        validation_error = validate_params
        return error(validation_error) if validation_error

        ApplicationRecord.transaction do
          rule.build_approval_rules_merge_request(merge_request: merge_request)
          rule.save!
          assign_approvers
        end

        success(rule: rule)
      rescue ActiveRecord::RecordInvalid => e
        # Returns errors.messages (Hash) to match v1 ApprovalRules::BaseService#error format.
        # Pre-validation errors above return strings for early, clear feedback.
        record = e.record || rule
        error(record.errors.messages, payload: { rule: record })
      end

      # Pre-validate params until model validations are added.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/595631
      def validate_params
        return "Name can't be blank" if params[:name].blank?
        return "Name is too long (maximum is 255 characters)" if params[:name].length > 255

        if params[:rule_type].present? && valid_rule_types.exclude?(params[:rule_type].to_s)
          return "'#{params[:rule_type]}' is not a valid rule_type"
        end

        return "Approvals required must be greater than or equal to 0" if approvals_required < 0

        nil
      end

      def approvals_required
        params.fetch(:approvals_required, 0).to_i
      end
      strong_memoize_attr :approvals_required

      def valid_rule_types
        MergeRequests::ApprovalRule.rule_types.keys
      end

      def rule
        MergeRequests::ApprovalRule.new(rule_attributes)
      end
      strong_memoize_attr :rule

      def rule_attributes
        {
          name: params[:name],
          approvals_required: approvals_required,
          rule_type: params[:rule_type] || :regular,
          origin: :merge_request,
          project_id: project.id
        }
      end

      def assign_approvers
        assign_users
        assign_groups
      end

      # Users must be project members (matches v1 ApprovalRules::Updater#filter_eligible_users!).
      def assign_users
        return if params[:user_ids].blank?

        users = project.members_among(User.id_in(params[:user_ids]))
        rule.approver_users = users if users.any?
      end

      # Groups must be accessible to current_user (matches v1 ApprovalRules::Updater#filter_eligible_groups!).
      def assign_groups
        return if params[:group_ids].blank?

        groups = Group.id_in(params[:group_ids]).accessible_to_user(current_user)
        rule.approver_groups = groups if groups.any?
      end
    end
  end
end

# frozen_string_literal: true

module MergeRequests
  module V2ApprovalRules
    class UpdateService < BaseService
      private

      def action
        return error('Rule not found') unless rule

        validation_error = validate_params
        return error(validation_error) if validation_error

        filter_approvers
        rule.update!(update_params)

        success(rule: rule.reset)
      rescue ActiveRecord::RecordInvalid => e
        record = e.record || rule
        ServiceResponse.error(message: record.errors.messages, payload: { rule: record })
      end

      def rule
        return @rule if defined?(@rule)

        @rule = find_rule
      end

      def find_rule
        merge_request.v2_approval_rules.find_by_id(params[:approval_rule_id])
      end

      # Pre-validate params until model validations are added.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/595631
      def validate_params
        return "Name can't be blank" if params.key?(:name) && params[:name].blank?
        return "Name is too long (maximum is 255 characters)" if params.key?(:name) && params[:name].length > 255

        if params.key?(:approvals_required) && approvals_required < 0
          return "Approvals required must be greater than or equal to 0"
        end

        nil
      end

      def approvals_required
        params[:approvals_required].to_i
      end

      def update_params
        @update_params ||= {}.tap do |attrs|
          attrs[:name] = params[:name] if params.key?(:name)
          attrs[:approvals_required] = approvals_required if params.key?(:approvals_required)
          attrs[:approver_users] = @filtered_users if @filtered_users
          attrs[:approver_groups] = @filtered_groups if @filtered_groups
        end
      end

      def filter_approvers
        filter_users if params.key?(:user_ids)
        filter_groups if params.key?(:group_ids)
      end

      # Users must be project members (matches v1 ApprovalRules::Updater#filter_eligible_users!).
      def filter_users
        @filtered_users = project.members_among(User.id_in(Array(params[:user_ids])))
      end

      # Groups must be accessible to current_user (matches v1 ApprovalRules::Updater#filter_eligible_groups!).
      def filter_groups
        groups = Group.id_in(Array(params[:group_ids])).accessible_to_user(current_user)
        groups += hidden_groups if keep_existing_hidden_groups?
        @filtered_groups = groups
      end

      def keep_existing_hidden_groups?
        !Gitlab::Utils.to_boolean(params[:remove_hidden_groups])
      end

      # TODO: Port project_groups visibility logic from ApprovalRules::GroupFinder.
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/595477
      def hidden_groups
        visible_group_ids = rule.approver_groups.accessible_to_user(current_user).map(&:id).to_set
        rule.approver_groups.reject { |group| visible_group_ids.include?(group.id) }
      end
    end
  end
end

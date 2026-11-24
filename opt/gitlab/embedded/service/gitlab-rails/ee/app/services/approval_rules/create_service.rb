# frozen_string_literal: true

module ApprovalRules
  class CreateService < ::ApprovalRules::BaseService
    include ::ApprovalRules::Updater

    # @param target [Project, MergeRequest, Group]
    def initialize(target, user, params)
      @target = target
      @rule = target.approval_rules.build
      @params = params

      # If merge request approvers are specified, they take precedence over project
      # approvers.
      # WIP, enable copying of group approval properties to merge request,
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/432799.
      copy_approval_project_rule_properties(params) if target.is_a?(MergeRequest)
      handle_any_approver_rule_creation(target, params)

      super(container: container, current_user: user, params: params)
    end

    def success
      merge_request_activity_counter
        .track_approval_rule_added_action(user: current_user)

      super
    end

    private

    attr_reader :target

    def authorized?
      can?(current_user, :create_approval_rule, target)
    end

    def copy_approval_project_rule_properties(params)
      return if params[:approval_project_rule_id].blank?

      approval_project_rule = @rule.project.approval_rules.find_by_id(params[:approval_project_rule_id])

      return if approval_project_rule.blank?

      params[:name] = approval_project_rule.name

      unless approvers_set?
        params[:users] = approval_project_rule.users
        params[:groups] = approval_project_rule.groups
      end
    end

    def handle_any_approver_rule_creation(target, params)
      unless approvers_present?
        params.reverse_merge!(rule_type: :any_approver, name: ApprovalRuleLike::ALL_MEMBERS)

        return
      end

      return if container.multiple_approval_rules_available?

      target.approval_rules.any_approver.delete_all
    end

    def approvers_set?
      @params.key?(:user_ids) || @params.key?(:group_ids) || @params.key?(:usernames)
    end

    def approvers_present?
      %i[user_ids group_ids users groups usernames].any? { |key| @params[key].present? }
    end
  end
end

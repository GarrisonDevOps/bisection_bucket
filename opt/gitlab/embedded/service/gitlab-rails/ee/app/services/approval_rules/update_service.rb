# frozen_string_literal: true

module ApprovalRules
  class UpdateService < ::ApprovalRules::BaseService
    include ::ApprovalRules::Updater

    attr_reader :rule, :keep_existing_hidden_groups

    def initialize(approval_rule, user, params)
      @rule = approval_rule
      @keep_existing_hidden_groups = !Gitlab::Utils.to_boolean(params.delete(:remove_hidden_groups))

      super(container: container, current_user: user, params: params)
    end

    def filter_eligible_groups!
      super

      # Append hidden groups unless removal is explicitly stated,
      # as hidden group ids are never passed to/back from clients for security reasons.
      # Union: a permitted hidden group may already be in params, and a duplicate re-inserts its join row.
      if params[:groups] && keep_existing_hidden_groups
        params[:groups] |= GroupFinder.new(rule, current_user).hidden_groups
      end
    end

    def success
      merge_request_activity_counter
        .track_approval_rule_edited_action(user: current_user)

      unless group_rule?
        ::ComplianceManagement::Standards::Gitlab::AtLeastTwoApprovalsWorker
          .perform_async({ 'project_id' => rule.project.id, 'user_id' => current_user&.id })

        ::ComplianceManagement::Standards::Soc2::AtLeastOneNonAuthorApprovalWorker
          .perform_async({ 'project_id' => rule.project.id, 'user_id' => current_user&.id })
      end

      super
    end

    private

    def authorized?
      can?(current_user, :update_approval_rule, rule)
    end
  end
end

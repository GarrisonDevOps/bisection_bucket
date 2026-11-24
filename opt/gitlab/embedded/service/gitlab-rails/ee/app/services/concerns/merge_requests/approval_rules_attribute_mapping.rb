# frozen_string_literal: true

module MergeRequests
  module ApprovalRulesAttributeMapping
    extend ActiveSupport::Concern

    def map_and_replace_approval_rules_attributes_to_v2
      return unless params[:approval_rules_attributes]

      map_approval_rules_attributes_to_v2
      params.delete(:approval_rules_attributes)
    end

    private

    def map_approval_rules_attributes_to_v2
      return unless params[:approval_rules_attributes]

      params[:v2_approval_rules_attributes] = params[:approval_rules_attributes].map do |rule|
        v2_rule = rule.dup.to_h
        v2_rule[:approver_user_ids] = rule[:user_ids]
        v2_rule[:approver_group_ids] = rule[:group_ids]
        v2_rule[:origin] = :merge_request
        v2_rule[:project_id] = project.id

        ActionController::Parameters.new(v2_rule).permit(
          :id,
          :_destroy,
          :rule_type,
          :name,
          :approvals_required,
          :origin,
          :project_id,
          approver_user_ids: [],
          approver_group_ids: []
        )
      end
    end
  end
end

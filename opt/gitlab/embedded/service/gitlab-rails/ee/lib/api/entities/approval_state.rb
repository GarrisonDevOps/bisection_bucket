# frozen_string_literal: true

module API
  module Entities
    class ApprovalState < Grape::Entity
      expose :merge_request, merge: true, using: ::API::Entities::IssuableEntity

      expose :merge_status,
        documentation: {
          type: 'String', example: 'can_be_merged',
          desc: 'Status of the merge request, such as `can_be_merged`. For every possible status, use ' \
            '`detailed_merge_status` from the merge requests endpoints instead.'
        } do |approval_state|
        approval_state.merge_request.public_merge_status
      end

      expose :approved?, as: :approved,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, the merge request has every approval its approval rules require.'
        }

      expose :approvals_required,
        documentation: { type: 'Integer', example: 2, desc: 'Number of approvals that the approval rules require.' }

      expose :approvals_left,
        documentation: {
          type: 'Integer', example: 2,
          desc: 'Number of approvals still required before the merge request is approved.'
        }

      expose :require_password_to_approve,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, approvers must authenticate again to approve. Deprecated. Use ' \
            '`require_reauthentication_to_approve` from the project approval configuration instead.'
        } do |approval_state|
        approval_state.project.require_password_to_approve?
      end

      expose :approved_by, using: ::API::Entities::Approvals,
        documentation: {
          type: '::API::Entities::Approvals', is_array: true,
          desc: 'Users who approved the merge request, whether or not their approvals satisfy an approval rule.'
        } do |approval_state|
        approval_state.merge_request.approvals
      end

      expose :suggested_approvers,
        using: ::API::Entities::UserBasic,
        documentation: {
          type: '::API::Entities::UserBasic', is_array: true,
          desc: 'Eligible approvers who have not approved the merge request yet.'
        } do |approval_state, options|
          approval_state.suggested_approvers(current_user: options[:current_user])
        end

      # @deprecated, reads from first regular rule instead
      expose :approvers,
        documentation: {
          type: 'Hash', is_array: true,
          desc: 'Users of the first `regular` or `any_approver` approval rule, each in a `user` object. ' \
            'Deprecated. Use the `/approval_state` endpoint instead.'
        } do |approval_state|
        # rubocop:disable Lint/AssignmentInCondition -- TODO: needs to be fixed
        if rule = approval_state.first_regular_rule
          rule.users.map do |user|
            { user: ::API::Entities::UserBasic.represent(user) }
          end
        else
          []
        end
        # rubocop:enable Lint/AssignmentInCondition
      end
      # @deprecated, reads from first regular rule instead
      expose :approver_groups,
        documentation: {
          type: 'Hash', is_array: true,
          desc: 'Groups of the first `regular` or `any_approver` approval rule, each in a `group` object. ' \
            'Deprecated. Use the `/approval_state` endpoint instead.'
        } do |approval_state|
        # rubocop:disable Lint/AssignmentInCondition -- TODO: needs to be fixed
        if rule = approval_state.first_regular_rule
          presenter = ::ApprovalRulePresenter.new(rule, current_user: options[:current_user])
          presenter.groups.map do |group|
            { group: ::API::Entities::Group.represent(group) }
          end
        else
          []
        end
        # rubocop:enable Lint/AssignmentInCondition
      end

      expose :user_has_approved,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, the current user has approved the merge request.'
        } do |approval_state, options|
        approval_state.merge_request.approved_by?(options[:current_user])
      end

      expose :user_can_approve,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, the current user can approve the merge request.'
        } do |approval_state, options|
        approval_state.eligible_for_approval_by?(options[:current_user])
      end

      expose :approval_rules_left, using: ::API::Entities::ApprovalRuleShort,
        documentation: {
          type: '::API::Entities::ApprovalRuleShort', is_array: true,
          desc: 'Approval rules that still require approvals.'
        }

      expose :has_approval_rules,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, at least one `regular` or `any_approver` approval rule applies to the merge request.'
        } do |approval_state|
        approval_state.user_defined_rules.present?
      end

      expose :merge_request_approvers_available,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, approval rules are available in the project.'
        } do |approval_state|
        # rubocop:disable Gitlab/FeatureAvailableUsage -- TODO: needs to be fixed
        approval_state.project.feature_available?(:merge_request_approvers)
        # rubocop:enable Gitlab/FeatureAvailableUsage
      end

      expose :multiple_approval_rules_available,
        documentation: {
          type: 'Boolean',
          desc: 'If `true`, the project can have more than one approval rule.'
        } do |approval_state|
        approval_state.project.multiple_approval_rules_available?
      end

      expose :invalid_approvers_rules, using: ::API::Entities::ApprovalRuleShort,
        documentation: {
          type: '::API::Entities::ApprovalRuleShort', is_array: true,
          desc: 'Approval rules that have fewer eligible approvers than the approvals they require.'
        }
    end
  end
end

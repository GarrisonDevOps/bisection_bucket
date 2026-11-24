# frozen_string_literal: true

module API
  class MergeRequestApprovalRules < ::API::Base
    include PaginationParams

    before { authenticate_non_get! }

    feature_category :source_code_management

    helpers do
      def find_merge_request_approval_rule(merge_request, id)
        merge_request.approval_rules.find(id)
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
      requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/merge_requests/:merge_request_iid/approval_rules' do
        desc 'List all approval rules for a merge request' do
          detail 'Lists all approval rules and any associated details for a specified merge request. Use the `page` ' \
            'and `per_page` pagination parameters to restrict the list of approval rules.'
          success ::API::Entities::MergeRequestApprovalRule
          is_array true
          tags %w[merge_request_approvals]
        end
        params do
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_merge_request_approval_rule, boundary_type: :project
        get '/', urgency: :low do
          merge_request = find_merge_request_with_access(params[:merge_request_iid])

          if Feature.enabled?(:v2_approval_rules, merge_request.project)
            present paginate(merge_request.v2_approval_rules), with: ::API::Entities::MergeRequestApprovalRule, current_user: current_user
          else
            present paginate(merge_request.approval_rules), with: ::API::Entities::MergeRequestApprovalRule, current_user: current_user
          end
        end

        desc 'Create an approval rule for a merge request' do
          detail 'Creates an approval rule for a specified merge request. If `approval_project_rule_id` is set with ' \
            'the ID of an existing approval rule from the project, this endpoint copies the values for `name`, ' \
            '`users`, and `groups` from the project rule, and uses the `approvals_required` value you specify.'
          success ::API::Entities::MergeRequestApprovalRule
          tags %w[merge_request_approvals]
        end
        params do
          requires :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
          requires :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
          optional :approval_project_rule_id, type: Integer, desc: 'ID of a project-level approval rule.'
          optional :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. If used with `usernames`, adds both lists of users.'
          optional :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers.'
          optional :usernames, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce, desc: 'Usernames of users to add as approvers. If used with `user_ids`, adds both lists of users.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :create_merge_request_approval_rule, boundary_type: :project
        post do
          merge_request = find_merge_request_with_access(params[:merge_request_iid], :update_approvers)
          result = ::ApprovalRules::CreateService.new(merge_request, current_user, declared_params(include_missing: false)).execute

          if result.success?
            present result[:rule], with: ::API::Entities::MergeRequestApprovalRule, current_user: current_user
          else
            render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
          end
        end

        params do
          requires :approval_rule_id, type: Integer, desc: 'ID of the merge request approval rule.'
        end
        segment ':approval_rule_id' do
          desc 'Retrieve an approval rule for a specific merge request' do
            detail 'Retrieves information about an approval rule for a specified merge request.'
            success ::API::Entities::MergeRequestApprovalRule
            tags %w[merge_request_approvals]
          end
          params do
            requires :approval_rule_id, type: Integer, desc: 'ID of the merge request approval rule.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_merge_request_approval_rule, boundary_type: :project
          get do
            merge_request = find_merge_request_with_access(params[:merge_request_iid])
            approval_rule = find_merge_request_approval_rule(merge_request, params[:approval_rule_id])

            present approval_rule, with: ::API::Entities::MergeRequestApprovalRule, current_user: current_user
          end

          desc 'Update an approval rule for a merge request' do
            detail 'Updates a specified approval rule for a merge request. This endpoint removes any approvers and ' \
              'groups not included in the `group_ids`, `user_ids`, or `usernames` attributes. The `report_approver` ' \
              'or `code_owner` rules are system-generated, and you cannot edit them.'
            success ::API::Entities::MergeRequestApprovalRule
            tags %w[merge_request_approvals]
          end
          params do
            requires :approval_rule_id, type: Integer, desc: 'ID of the merge request approval rule.'
            optional :name, type: String, desc: 'Name of the approval rule. Limited to 1024 characters.'
            optional :approvals_required, type: Integer, desc: 'Number of required approvals for the rule.'
            optional :user_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of users to add as approvers. If used with `usernames`, adds both lists of users.'
            optional :group_ids, type: Array[Integer], coerce_with: ::API::Validations::Types::CommaSeparatedToIntegerArray.coerce, desc: 'IDs of groups to add as approvers.'
            optional :usernames, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce, desc: 'Usernames of users to add as approvers. If used with `user_ids`, adds both lists of users.'
            optional :remove_hidden_groups, type: Boolean, desc: 'If `true`, removes hidden groups.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :update_merge_request_approval_rule, boundary_type: :project
          put do
            merge_request = find_merge_request_with_access(params[:merge_request_iid], :update_approvers)
            params = declared_params(include_missing: false)
            approval_rule = find_merge_request_approval_rule(merge_request, params.delete(:approval_rule_id))
            result = ::ApprovalRules::UpdateService.new(approval_rule, current_user, params).execute

            if result.success?
              present result[:rule], with: ::API::Entities::MergeRequestApprovalRule, current_user: current_user
            else
              render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
            end
          end

          desc 'Delete an approval rule for a merge request' do
            detail 'Deletes a specified approval rule for a merge request. The `report_approver` or `code_owner` ' \
              'rules are system-generated, and you cannot edit them.'
            success [{ code: 204 }]
            tags %w[merge_request_approvals]
          end
          params do
            requires :approval_rule_id, type: Integer, desc: 'ID of the merge request approval rule.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :delete_merge_request_approval_rule, boundary_type: :project
          delete do
            merge_request = find_merge_request_with_access(params[:merge_request_iid], :update_approvers)
            approval_rule = find_merge_request_approval_rule(merge_request, params[:approval_rule_id])

            destroy_conditionally!(approval_rule) do |rule|
              result = ::ApprovalRules::MergeRequestRuleDestroyService.new(rule, current_user).execute

              if result.error?
                render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
              end
            end
          end
        end
      end
    end
  end
end

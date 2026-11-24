# frozen_string_literal: true

module EE
  module API
    module MergeRequestApprovals
      extend ActiveSupport::Concern

      prepended do
        before { authenticate_non_get! }

        helpers do
          def present_merge_request_approval_state(presenter:, target_branch: nil)
            merge_request = find_merge_request_with_access(params[:merge_request_iid])

            present(
              merge_request.approval_state(target_branch: target_branch),
              with: presenter,
              current_user: current_user
            )
          end
        end

        params do
          requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
          requires :merge_request_iid, type: Integer, desc: 'Internal ID of the merge request.'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          segment ':id/merge_requests/:merge_request_iid' do
            desc 'List approval rules for merge request', {
              success: ::API::Entities::MergeRequestApprovalSettings,
              hidden: true,
              tags: ['merge_request_approvals']
            }
            params do
              optional :target_branch, type: String,
                desc: 'Branch that scoped approval rules apply to',
                documentation: { example: 'main' }
            end
            route_setting :authorization, permissions: :read_approval_rule, boundary_type: :project
            get 'approval_settings' do
              present_merge_request_approval_state(
                presenter: ::API::Entities::MergeRequestApprovalSettings,
                target_branch: declared_params[:target_branch]
              )
            end

            desc 'Retrieve approval details for a merge request' do
              detail 'Retrieves approval details for a specified merge request. If a user has modified the approval ' \
                'rules for the merge request, the response includes `approval_rules_overwritten`. In each rule, ' \
                '`approved` is `true` when the rule is approved, and `approved_by` lists the users who approved ' \
                'it. Users who do not match an approval rule are not returned. To get all approving users, use ' \
                '`GET /projects/:id/merge_requests/:merge_request_iid/approvals`.'
              success ::API::Entities::MergeRequestApprovalState
              tags ['merge_request_approvals']
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :read_merge_request_approval_state, boundary_type: :project
            get 'approval_state' do
              present_merge_request_approval_state(presenter: ::API::Entities::MergeRequestApprovalState)
            end

            # Deprecated in favor of approval rules API
            desc 'Change approval-related configuration' do
              detail 'Deprecated in 16.0. Use the merge request approvals API instead.'
              success ::API::Entities::ApprovalState
              deprecated true
              tags ['merge_request_approvals']
            end
            params do
              requires :approvals_required, type: Integer,
                desc: 'Number of approvals required for the merge request.',
                documentation: { example: 2 }
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :update_approval_rule, boundary_type: :project
            post 'approvals' do
              merge_request = find_merge_request_with_access(params[:merge_request_iid], :update_merge_request)

              error!('Overriding approvals is disabled', 422) if merge_request.project.disable_overriding_approvers_per_merge_request

              approval_rule = merge_request.approval_rules.any_approver.first

              approval_params = declared_params(include_missing: false)

              result = if approval_rule
                         ::ApprovalRules::UpdateService.new(approval_rule, current_user, approval_params).execute
                       else
                         ::ApprovalRules::CreateService.new(merge_request, current_user, approval_params).execute
                       end

              if result[:status] == :success
                present_approval(merge_request)
              else
                render_api_error!(result.message, result.cause.access_denied? ? 403 : 400)
              end
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module API
    module Deployments
      extend ActiveSupport::Concern

      prepended do
        params do
          requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
        end
        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Approve or reject a deployment' do
            detail 'Approves or rejects a deployment.'
            success ::API::Entities::Deployments::Approval
            tags %w[deploy_resources]
          end
          params do
            requires :deployment_id, type: Integer, desc: 'ID of the deployment.'
            requires :status, type: String, values: ::Deployments::Approval.statuses.keys, desc: 'Status of the approval.'
            optional :comment, type: String, desc: 'Comment to go with the approval.'
            optional :represented_as, type: String, desc: 'Name of the user, group, or role to use for the approval when the user belongs to [multiple approval rules](https://docs.gitlab.com/ci/environments/deployment_approvals/#add-multiple-approval-rules).'
          end
          route_setting :authentication, job_token_allowed: true
          route_setting :tier, :premium
          route_setting :authorization, permissions: :approve_deployment, boundary_type: :project,
            job_token_policies: :admin_deployments
          post ':id/deployments/:deployment_id/approval' do
            authorize! :read_deployment, user_project

            deployment = user_project.deployments.find(params[:deployment_id])

            result = ::Deployments::ApprovalService.new(user_project, current_user, declared_params(include_missing: false))
                                                   .execute(deployment, params[:status])

            if result[:status] == :success
              present(result[:approval], with: ::API::Entities::Deployments::Approval, current_user: current_user)
            else
              render_api_error!(result[:message], 400)
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module API
    module MergeRequests
      extend ActiveSupport::Concern

      prepended do
        helpers do
          params :optional_params_ee do
            optional :approvals_before_merge, type: Integer, desc: 'Number of approvals required before the merge request can be merged. [Deprecated](https://gitlab.com/gitlab-org/gitlab/-/issues/353097) in GitLab 16.0. Premium and Ultimate only.'
            optional :approval_rules_attributes, type: Array, documentation: { hidden: true } do
              optional :id, type: Integer, desc: 'The ID of a rule'
              optional :approvals_required, type: Integer, desc: 'Total number of approvals required'
            end
          end

          params :optional_merge_requests_search_params do
            optional :approver_ids,
              types: [String, Array], array_none_any: true,
              desc: 'Return merge requests that have all specified users as eligible approvers according to the approval rules. `None` returns merge requests with no eligible approvers, and `Any` returns merge requests with at least one eligible approver. Premium and Ultimate only.'
            optional :approved_by_ids,
              types: [String, Array], array_none_any: true,
              desc: 'Return merge requests approved by all the users with the given `id`, up to 5 users. `None` returns merge requests with no approvals, and `Any` returns merge requests with an approval.'
            optional :approved_by_usernames,
              types: [String, Array], array_none_any: true,
              desc: 'Return merge requests approved by all the users with the given `username`, up to 5 users. `None` returns merge requests with no approvals, and `Any` returns merge requests with an approval.'
            mutually_exclusive :approved_by_ids, :approved_by_usernames
          end

          params :optional_merge_params_ee do
            optional :skip_merge_train,
              type: Grape::API::Boolean,
              desc: 'If `true`, skips the merge train restart when merging immediately in a project configured for merge trains.'
          end

          def ci_params
            super.merge(skip_merge_train: params[:skip_merge_train])
          end

          def validate_immediate_merge!(merge_request)
            return unless merge_request.target_project.merge_train_enforced_for?(current_user)

            not_allowed!(
              'This project requires merge requests to go through the merge train. ' \
                'Set auto_merge to true to add this merge request to the train.'
            )
          end
        end

        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Create a CI configuration merge request' do
            detail 'Creates a merge request to add CI configuration to a specified project.'
            success ::API::Entities::MergeRequest
            failure [
              { code: 400, message: 'Bad request' },
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[projects merge_requests]
          end
          route_setting :authorization, permissions: :create_merge_request, boundary_type: :project
          post ':id/create_ci_config', feature_category: :compliance_management do
            authorize! :create_merge_request_in, user_project

            result = ComplianceManagement::Projects::CreateCiConfigService.new(user_project, current_user).execute

            if result[:status] == :success
              present result[:merge_request], with: ::API::Entities::MergeRequest, current_user: current_user, project: user_project
            else
              render_api_error!(result[:message], result[:http_status])
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module API
  class MergeRequestApprovalSettings < ::API::Base
    feature_category :source_code_management

    before do
      authenticate!
    end

    helpers do
      params :merge_request_approval_settings do
        optional :allow_author_approval, type: Boolean, desc: 'If `true`, authors can self-approve merge requests.', allow_blank: false
        optional :allow_committer_approval, type: Boolean, desc: 'If `true`, committers can self-approve merge requests.', allow_blank: false
        optional :allow_overrides_to_approver_list_per_merge_request,
          type: Boolean, desc: 'If `true`, allows overriding approvers per merge request.', allow_blank: false
        optional :retain_approvals_on_push, type: Boolean, desc: 'If `true`, retains the approval count on a new push.', allow_blank: false
        optional :selective_code_owner_removals, type: Boolean, desc: 'If `true`, resets approvals from Code Owners if their files change. To use this field, `retain_approvals_on_push` must be `true`.', allow_blank: false
        optional :require_password_to_approve,
          type: Boolean, desc: 'If `true`, requires approvers to authenticate before approving. Deprecated in GitLab 16.9. Use `require_reauthentication_to_approve` instead, which takes precedence if both are provided.', allow_blank: false

        optional :require_reauthentication_to_approve,
          type: Boolean, desc: 'If `true`, requires approvers to authenticate before approving. [Introduced](https://gitlab.com/gitlab-org/gitlab/-/issues/431346) in GitLab 17.1.', allow_blank: false

        at_least_one_of :allow_author_approval,
          :allow_committer_approval,
          :allow_overrides_to_approver_list_per_merge_request,
          :retain_approvals_on_push,
          :selective_code_owner_removals,
          :require_password_to_approve,
          :require_reauthentication_to_approve
      end

      # If the new version of the parameter is used mirror it to the old param
      # in order to keep both field in sync until full removal
      # Mirror reauthentication to password for approval
      # https://gitlab.com/gitlab-org/gitlab/-/issues/431346
      def setting_params
        normalized_params = declared_params(include_missing: false)

        if normalized_params.key?(:require_reauthentication_to_approve)
          normalized_params[:require_password_to_approve] = normalized_params[:require_reauthentication_to_approve]
        elsif normalized_params.key?(:require_password_to_approve)
          normalized_params[:require_reauthentication_to_approve] = normalized_params[:require_password_to_approve]
        end

        normalized_params
      end
    end

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/merge_request_approval_setting' do
        desc 'Retrieve MR approval settings for a project' do
          detail 'Retrieves the merge request approval settings for a specified project.'
          success code: 200, model: ::API::Entities::MergeRequestApprovalSetting
          failure [
            { code: 403, message: 'Forbidden' }
          ]
          tags %w[merge_request_approvals]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_merge_request_approval_setting, boundary_type: :project
        get '/', urgency: :medium do
          authorize! :read_merge_request_approval_setting, user_project

          group = user_project.group.present? ? user_project.root_ancestor : nil
          setting = ComplianceManagement::MergeRequestApprovalSettings::Resolver.new(group, project: user_project).execute

          present setting, with: ::API::Entities::MergeRequestApprovalSetting
        end
        desc 'Update MR approval settings for a project' do
          detail 'Updates the merge request approval settings for a specified project.'
          success code: 200, model: ::API::Entities::MergeRequestApprovalSetting
          failure [
            { code: 400, message: 'Validation error' },
            { code: 403, message: 'Forbidden' }
          ]
          tags %w[merge_request_approvals]
        end
        params do
          use :merge_request_approval_settings
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_merge_request_approval_setting, boundary_type: :project
        put do
          authorize! :update_merge_request_approval_setting, user_project

          response = ::MergeRequestApprovalSettings::UpdateService
                       .new(container: user_project, current_user: current_user, params: setting_params).execute

          if response.success?
            group = user_project.group.present? ? user_project.root_ancestor : nil

            setting = ComplianceManagement::MergeRequestApprovalSettings::Resolver.new(group, project: user_project).execute

            present setting, with: ::API::Entities::MergeRequestApprovalSetting
          else
            render_api_error!(response.message, :bad_request)
          end
        end
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/merge_request_approval_setting' do
        desc 'Retrieve MR approval settings for a group' do
          detail 'Retrieves the merge request approval settings for a specified group.'
          success code: 200, model: ::API::Entities::MergeRequestApprovalSetting
          failure [
            { code: 403, message: 'Forbidden' }
          ]
          tags %w[merge_request_approvals]
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_merge_request_approval_setting, boundary_type: :group
        get do
          authorize! :read_merge_request_approval_setting, user_group

          setting = ComplianceManagement::MergeRequestApprovalSettings::Resolver.new(user_group).execute

          present setting, with: ::API::Entities::MergeRequestApprovalSetting
        end

        desc 'Update MR approval settings for a group' do
          detail 'Updates the merge request approval settings for a specified group.'
          success code: 200, model: ::API::Entities::MergeRequestApprovalSetting
          failure [
            { code: 400, message: 'Validation error' },
            { code: 403, message: 'Forbidden' }
          ]
          tags %w[merge_request_approvals]
        end
        params do
          use :merge_request_approval_settings
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :update_merge_request_approval_setting, boundary_type: :group
        put do
          authorize! :update_merge_request_approval_setting, user_group

          response = ::MergeRequestApprovalSettings::UpdateService
            .new(container: user_group, current_user: current_user, params: setting_params).execute

          if response.success?
            setting = ComplianceManagement::MergeRequestApprovalSettings::Resolver.new(user_group).execute

            present setting, with: ::API::Entities::MergeRequestApprovalSetting
          else
            render_api_error!(response.message, :bad_request)
          end
        end
      end
    end
  end
end

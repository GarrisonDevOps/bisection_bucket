# frozen_string_literal: true

module API
  class ProjectApprovalSettings < ::API::Base
    before { authenticate! }
    before { check_feature_availability }

    helpers ::API::Helpers::ProjectApprovalRulesHelpers

    feature_category :source_code_management

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end
    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/approval_settings' do
        desc 'Get all project approval rules' do
          detail 'Private API subject to change'
          success ::API::Entities::ProjectApprovalSettings
          tags %w[approval_rules]
        end
        params do
          optional :target_branch, type: String, desc: 'Branch that scoped approval rules apply to.'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_approval_rule, boundary_type: :project
        get do
          authorize_read_project_approval_rule!

          present(
            user_project,
            with: ::API::Entities::ProjectApprovalSettings,
            current_user: current_user,
            target_branch: declared_params[:target_branch]
          )
        end

        segment 'rules' do
          desc 'Create new approval rule' do
            detail 'Private API subject to change'
            success ::API::Entities::ProjectApprovalSettingRule
            tags %w[approval_rules]
          end
          params do
            use :create_project_approval_rule
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :create_approval_rule, boundary_type: :project
          post do
            create_project_approval_rule(present_with: ::API::Entities::ProjectApprovalSettingRule)
          end

          params do
            requires :approval_rule_id, type: Integer, desc: 'The ID of an approval rule'
          end
          segment ':approval_rule_id' do
            desc 'Update approval rule' do
              detail 'Private API subject to change'
              success ::API::Entities::ProjectApprovalSettingRule
              tags %w[approval_rules]
            end
            params do
              use :update_project_approval_rule
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :update_approval_rule, boundary_type: :project
            put do
              update_project_approval_rule(present_with: ::API::Entities::ProjectApprovalSettingRule)
            end

            desc 'Delete an approval rule' do
              detail 'Private API subject to change'
              success [{ code: 204 }]
              tags %w[approval_rules]
            end
            params do
              use :delete_project_approval_rule
            end
            route_setting :tier, :premium
            route_setting :authorization, permissions: :delete_approval_rule, boundary_type: :project
            delete do
              destroy_project_approval_rule
            end
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module API
  module Analytics
    class GroupActivityAnalytics < ::API::Base
      feature_category :value_stream_management
      urgency :low

      before do
        authenticate!
      end

      helpers do
        def group
          @group ||= find_group_by_full_path!(params[:group_path])
        end

        def calculator
          @calculator ||=
            ::Analytics::GroupActivityCalculator.new(group, current_user)
        end
      end

      resource :analytics do
        resource :group_activity do
          desc 'Retrieve count of recently created issues for a group' do
            tags %w[analytics]
            detail 'Retrieves the count of recently created issues for a specified group.'
            success ::API::Entities::Analytics::GroupActivity::IssuesCount
          end
          params do
            requires :group_path, type: String, desc: 'Group path.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_activity_analytics,
            boundary_type: :group, boundary_param: :group_path
          get 'issues_count' do
            authorize! :read_group_activity_analytics, group

            present(
              calculator,
              with: ::API::Entities::Analytics::GroupActivity::IssuesCount
            )
          end

          desc 'Retrieve count of recently created merge requests for a group' do
            tags %w[analytics]
            detail 'Retrieves the count of recently created merge requests for a specified group.'
            success ::API::Entities::Analytics::GroupActivity::MergeRequestsCount
          end
          params do
            requires :group_path, type: String, desc: 'Group path.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_activity_analytics,
            boundary_type: :group, boundary_param: :group_path
          get 'merge_requests_count' do
            authorize! :read_group_activity_analytics, group

            present(
              calculator,
              with: ::API::Entities::Analytics::GroupActivity::MergeRequestsCount
            )
          end

          desc 'Retrieve count of members recently added to a group' do
            tags %w[analytics]
            detail 'Retrieves the count of members recently added to a specified group.'
            success ::API::Entities::Analytics::GroupActivity::NewMembersCount
          end
          params do
            requires :group_path, type: String, desc: 'Group path.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :read_activity_analytics,
            boundary_type: :group, boundary_param: :group_path
          get 'new_members_count' do
            authorize! :read_group_activity_analytics, group

            present(
              calculator,
              with: ::API::Entities::Analytics::GroupActivity::NewMembersCount
            )
          end
        end
      end
    end
  end
end

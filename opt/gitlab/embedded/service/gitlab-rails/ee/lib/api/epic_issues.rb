# frozen_string_literal: true

module API
  class EpicIssues < ::API::Base
    include PaginationParams

    feature_category :portfolio_management
    urgency :low

    before do
      authenticate!
      authorize_epics_feature!
    end

    helpers ::API::Helpers::EpicsHelpers

    helpers do
      def link
        @link ||= epic.epic_issues.find(params[:epic_issue_id])
      end

      def related_issues(epic)
        work_children = ::WorkItems::LegacyEpics::WorkItemAsEpic.epic_issue_api_preloads(
          ::WorkItems::LegacyEpics::WorkItemAsEpic.new(epic.work_item).epic_issues
        ).with_api_entity_associations

        ::Kaminari.paginate_array(Ability.issues_readable_by_user(work_children, current_user))
      end

      def authorize_can_assign_to_epic!(issue)
        forbidden! unless can?(current_user, :read_epic, epic) && can?(current_user, :admin_issue_relation, issue)
      end
    end

    params do
      requires :id, types: [Integer, String], desc: 'ID or URL-encoded path of the group.', documentation: { example: '1' }
    end

    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'Update a related epic link' do
        detail 'Updates the relation of a specified issue to an epic.'
        is_array true
        success ::API::Entities::EpicIssue
        failure [
          { code: 400, message: 'Issue could not be moved!' },
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[epics]
      end
      params do
        requires :epic_iid, types: [Integer, String], desc: 'Internal ID of the epic.', documentation: { example: 5 }
        requires :epic_issue_id, types: [Integer, String], desc: 'ID of the epic-issue association to update.', documentation: { example: 11 }
        optional :move_before_id, types: [Integer, String], desc: 'ID of the epic-issue association to position before the issue.', documentation: { example: 20 }
        optional :move_after_id, types: [Integer, String], desc: 'ID of the epic-issue association to position after the issue.', documentation: { example: 25 }
        use :pagination
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :update_epic_issue, boundary_type: :group
      put ':id/(-/)epics/:epic_iid/issues/:epic_issue_id' do
        authorize_can_assign_to_epic!(link.issue)

        update_params = {
          move_before_id: params[:move_before_id],
          move_after_id: params[:move_after_id]
        }

        result = ::WorkItems::LegacyEpics::EpicIssues::UpdateService.new(link, current_user, update_params).execute

        if result
          present paginate(related_issues(epic)),
            with: ::API::Entities::EpicIssue,
            current_user: current_user
        else
          render_api_error!({ error: "Issue could not be moved!" }, 400)
        end
      end

      [':id/epics/:epic_iid/issues', ':id/-/epics/:epic_iid/issues'].each do |path|
        desc 'List all issues for an epic' do
          detail 'Lists all issues assigned to a specified epic that are available to the authenticated user. ' \
            'Responses are paginated and return 20 results by default.'
          is_array true
          success ::API::Entities::EpicIssue
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags %w[epics]
        end
        params do
          requires :epic_iid, types: [Integer, String], desc: 'Internal ID of the epic.', documentation: { example: 5 }
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic_issue, boundary_type: :group
        get path do
          authorize_can_read!

          present paginate(related_issues(epic)),
            with: ::API::Entities::EpicIssue,
            current_user: current_user,
            include_subscribed: false
        end
      end

      desc 'Add an issue to an epic' do
        detail 'Adds a specified issue to an epic. If the issue already belongs to another epic, ' \
          'it is removed from the original epic.'
        success ::API::Entities::EpicIssueLink
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'No matching issue found' },
          { code: 409, message: 'Issue already assigned' }
        ]
        tags %w[epics]
      end
      params do
        requires :epic_iid, types: [Integer, String], desc: 'Internal ID of the epic.', documentation: { example: 5 }
        requires :issue_id, types: [Integer, String], desc: 'ID of the issue.', documentation: { example: 55 }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :create_epic_issue, boundary_type: :group
      # rubocop: disable CodeReuse/ActiveRecord
      post ':id/(-/)epics/:epic_iid/issues/:issue_id' do
        authorize_can_read!
        issue = Issue.find(params[:issue_id])
        authorize!(:admin_issue_relation, issue)

        create_params = { target_issuable: issue }

        result = ::WorkItems::LegacyEpics::EpicIssues::CreateService.new(epic, current_user, create_params).execute

        if result[:status] == :success
          epic_issue_link = EpicIssue.find_by!(epic: epic, issue: issue)

          present epic_issue_link, with: ::API::Entities::EpicIssueLink
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord

      desc 'Remove an issue from the epic' do
        detail 'Removes an issue from the epic. Does not delete the issue.'
        success code: 200, model: ::API::Entities::EpicIssueLink
        failure [
          { code: 401, message: 'Unauthorized' },
          { code: 403, message: 'Forbidden' },
          { code: 404, message: 'Not found' }
        ]
        tags %w[epics]
      end
      params do
        requires :epic_iid, types: [Integer, String], desc: 'Internal ID of the epic.', documentation: { example: 5 }
        requires :epic_issue_id, types: [Integer, String], desc: 'ID of the association.', documentation: { example: 11 }
      end
      route_setting :tier, :premium
      route_setting :authorization, permissions: :delete_epic_issue, boundary_type: :group
      delete ':id/(-/)epics/:epic_iid/issues/:epic_issue_id' do
        authorize_can_assign_to_epic!(link.issue)
        result = ::WorkItems::LegacyEpics::EpicIssues::DestroyService.new(link, current_user).execute

        if result[:status] == :success
          present link, with: ::API::Entities::EpicIssueLink
        else
          render_api_error!(result[:message], result[:http_status])
        end
      end
    end
  end
end

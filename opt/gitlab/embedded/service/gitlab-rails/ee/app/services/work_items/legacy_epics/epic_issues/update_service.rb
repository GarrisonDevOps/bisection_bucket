# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicIssues
      class UpdateService < BaseService
        def initialize(epic_issue, user, params)
          @epic_issue = epic_issue
          @current_user = user
          @params = params
        end

        def execute
          parent_link = @epic_issue.work_item_parent_link
          return error('No parent link found', 404) unless parent_link

          adjacent_item = find_adjacent_work_item
          if (params[:move_before_id] || params[:move_after_id]) && !adjacent_item
            return error('No parent link found', 404)
          end

          reorder_params = {
            target_issuable: @epic_issue.work_item,
            adjacent_work_item: adjacent_item,
            relative_position: determine_position
          }

          ::WorkItems::ParentLinks::ReorderService.new(
            parent_link.work_item_parent,
            @current_user,
            reorder_params
          ).execute
        end

        private

        attr_reader :epic_issue, :current_user, :params

        # rubocop: disable CodeReuse/ActiveRecord -- need find_by to validate adjacent epic issue
        def find_adjacent_work_item
          epic_issue_id = params[:move_before_id] || params[:move_after_id]
          return unless epic_issue_id

          adjacent_epic_issue = epic.epic_issues.find_by(id: epic_issue_id)
          adjacent_epic_issue&.work_item
        end
        # rubocop: enable CodeReuse/ActiveRecord

        def determine_position
          return 'AFTER' if params[:move_before_id]
          return 'BEFORE' if params[:move_after_id]

          nil
        end

        def epic
          epic_issue.epic
        end
      end
    end
  end
end

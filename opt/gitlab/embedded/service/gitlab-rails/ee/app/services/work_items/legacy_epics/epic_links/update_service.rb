# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicLinks
      class UpdateService < BaseService
        def initialize(epic, user, params)
          @epic = epic
          @current_user = user
          @params = params
        end

        def execute
          return not_found unless epic&.work_item
          # ReorderService doesn't check subepics license, so we need to check it here
          return not_found unless can?(current_user, :admin_epic_tree_relation, epic)
          return success unless move_params_present?

          parent_work_item = epic.work_item.work_item_parent
          return not_found unless parent_work_item

          validate_sibling_epics!

          result = ::WorkItems::ParentLinks::ReorderService.new(
            parent_work_item,
            current_user,
            reorder_params
          ).execute

          transform_result(result)
        rescue ActiveRecord::RecordNotFound
          error('Epic not found for given params', 422)
        end

        private

        attr_reader :epic, :current_user, :params

        def move_params_present?
          params[:move_before_id].present? || params[:move_after_id].present?
        end

        def validate_sibling_epics!
          before_sibling_epic if params[:move_before_id]
          after_sibling_epic if params[:move_after_id]
        end

        def reorder_params
          {
            target_issuable: epic.work_item,
            adjacent_work_item: adjacent_work_item,
            relative_position: relative_position
          }
        end

        def adjacent_work_item
          adjacent_epic.work_item
        end

        def adjacent_epic
          params[:move_before_id] ? before_sibling_epic : after_sibling_epic
        end

        def before_sibling_epic
          @before_sibling_epic ||= find_sibling_epic!(params[:move_before_id])
        end

        def after_sibling_epic
          @after_sibling_epic ||= find_sibling_epic!(params[:move_after_id])
        end

        def find_sibling_epic!(epic_id)
          Epic.in_work_item_parents(epic.parent.issue_id).find(epic_id)
        end

        def relative_position
          return 'AFTER' if params[:move_before_id]

          'BEFORE'
        end

        def not_found
          error('Epic not found for given params', 404)
        end

        def transform_result(result)
          return success if result[:status] == :success

          case result[:http_status]
          when 404
            error('Epic not found for given params', 422)
          when 422
            error(_("Couldn't reorder child due to an internal error."), 422)
          else
            error(result[:message], result[:http_status] || 422)
          end
        end
      end
    end
  end
end

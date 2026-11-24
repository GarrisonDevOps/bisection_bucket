# frozen_string_literal: true

module API
  class EpicBoards < ::API::Base
    include PaginationParams

    feature_category :planning_views
    urgency :low

    before do
      authenticate!
      authorize_epics_feature!
    end

    helpers ::API::Helpers::EpicsHelpers

    helpers do
      def epic_board
        epic_boards.find(params[:board_id])
      end

      def epic_boards
        ::Boards::EpicBoardsFinder.new(user_group).execute.with_api_entity_associations
      end

      def epic_lists
        epic_board.destroyable_lists.preload_associated_models
      end
    end

    params do
      requires :id, type: String, desc: 'ID or URL-encoded path of the group.', documentation: { example: '1' }
    end
    resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      segment ':id/epic_boards' do
        desc 'List all epic boards in a group' do
          detail 'Lists all epic boards for a specified group. This feature was introduced in GitLab 15.9.'
          success Entities::EpicBoard
          is_array true
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags ['epics']
        end
        params do
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic_board, boundary_type: :group
        get '/' do
          authorize! :read_epic_board, user_group

          present paginate(epic_boards), with: Entities::EpicBoard
        end

        desc 'Retrieve a group epic board' do
          detail 'Retrieves a specified group epic board. This feature was introduced in GitLab 15.9.'
          success Entities::EpicBoard
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags ['epics']
        end
        params do
          requires :board_id, type: Integer, desc: 'ID of the epic board.', documentation: { example: 1 }
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic_board, boundary_type: :group
        get '/:board_id' do
          authorize!(:read_epic_board, user_group)

          present epic_board, with: Entities::EpicBoard
        end
      end

      params do
        requires :board_id, type: Integer, desc: 'ID of the epic board.', documentation: { example: 1 }
      end
      segment ':id/epic_boards/:board_id' do
        desc 'List all group epic board lists' do
          detail 'Lists all group epic board lists for a specified board. Does not include `open` and ' \
            '`closed` lists. This feature was introduced in GitLab 15.9.'
          success Entities::EpicBoards::List
          is_array true
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags ['epics']
        end
        params do
          use :pagination
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic_board_list, boundary_type: :group
        get '/lists' do
          authorize!(:read_epic_board, epic_board)

          present paginate(epic_lists), with: Entities::EpicBoards::ListDetails
        end

        desc 'Retrieve a group epic board list' do
          detail 'Retrieves a specified group epic board list. This feature was introduced in GitLab 15.9.'
          success Entities::EpicBoards::List
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
          tags ['epics']
        end
        params do
          requires :list_id, type: Integer, desc: "ID of the epic board's list.", documentation: { example: 1 }
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_epic_board_list, boundary_type: :group
        get '/lists/:list_id' do
          authorize!(:read_epic_board, epic_board)

          present epic_lists.find(params[:list_id]), with: Entities::EpicBoards::ListDetails
        end
      end
    end
  end
end

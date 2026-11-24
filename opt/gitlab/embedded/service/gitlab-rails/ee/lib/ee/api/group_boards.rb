# frozen_string_literal: true

module EE
  module API
    class GroupBoards < ::API::Base
      include ::API::PaginationParams
      include ::API::BoardsResponses

      prepend EE::API::BoardsResponses # rubocop: disable Cop/InjectEnterpriseEditionModule

      feature_category :planning_views
      urgency :low

      before do
        authenticate!
      end

      helpers do
        def board_parent
          user_group
        end
      end

      params do
        requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
      end

      resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        segment ':id/boards' do
          desc 'Create a group issue board' do
            detail 'Creates a group issue board for a specified group.'
            success ::API::Entities::Board
            tags ['boards']
          end
          params do
            requires :name, type: String, desc: 'Name of the board.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :create_issue_board, boundary_type: :group
          post '/' do
            authorize!(:admin_issue_board, board_parent)

            create_board
          end

          desc 'Delete a group issue board' do
            detail 'Deletes a specified group issue board.'
            success ::API::Entities::Board
            tags ['boards']
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :delete_issue_board, boundary_type: :group
          delete '/:board_id' do
            authorize!(:admin_issue_board, board_parent)

            delete_board
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Mutations
  module Boards
    module EpicBoards
      class Update < Base
        graphql_name 'EpicBoardUpdate'

        authorize_granular_token permissions: :update_epic_board, boundary_argument: :id,
          boundary: :resource_parent, boundary_type: :group

        include Mutations::Boards::CommonMutationArguments
        prepend Mutations::Boards::ScopedBoardMutation

        argument :id,
          ::Types::GlobalIDType[::Boards::EpicBoard],
          required: true,
          description: 'Epic board global ID.'

        field :epic_board,
          Types::Boards::EpicBoardType,
          null: true,
          description: 'Updated epic board.'

        def resolve(**args)
          board = authorized_find!(id: args[:id])

          ::Boards::EpicBoards::UpdateService.new(board.resource_parent, current_user, args).execute(board)

          {
            epic_board: board.reset,
            errors: errors_on_object(board)
          }
        end
      end
    end
  end
end

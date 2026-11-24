# frozen_string_literal: true

module Boards
  module Epics
    class MoveService < Boards::BaseItemMoveService
      extend ::Gitlab::Utils::Override

      private

      def update(epic, epic_modification_params)
        RepositionService.new(epic: epic, current_user: current_user, params: epic_modification_params).execute

        return unless requires_update_service?(epic_modification_params)

        ::WorkItems::LegacyEpics::UpdateService.new(group: epic.group, current_user: current_user, params: epic_modification_params).execute(epic)
      end

      def board
        @board ||= parent.epic_boards.find(params[:board_id])
      end

      def moving_to_list_items_relation
        Boards::Epics::ListService.new(board.resource_parent, current_user, board_id: board.id, id: moving_to_list.id).execute
      end

      override :board_label_ids
      def board_label_ids
        ::Label.ids_on_epic_board(board.id)
      end

      override :reposition_params
      def reposition_params(reposition_ids)
        super.merge(list_id: params[:to_list_id], board_id: board.id, board_group: parent)
      end

      def requires_update_service?(params)
        params.key?(:add_label_ids) ||
          params.key?(:remove_label_ids) ||
          params.key?(:state_event)
      end
    end
  end
end

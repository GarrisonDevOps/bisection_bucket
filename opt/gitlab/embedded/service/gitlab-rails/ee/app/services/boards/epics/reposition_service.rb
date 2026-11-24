# frozen_string_literal: true

module Boards
  module Epics
    class RepositionService < ::Issues::BaseService
      extend ::Gitlab::Utils::Override

      def initialize(epic:, current_user:, params:)
        @epic = epic
        @current_user = current_user
        @params = params
      end

      def execute
        return unless Ability.allowed?(current_user, :update_epic, epic)

        @epic_board_id = params.delete(:board_id)

        return unless params[:move_between_ids]
        return unless epic_board_id

        # we want to create missing only for the epic being moved
        # other records are handled by PositionCreateService
        fill_missing_positions_before

        # rubocop: disable CodeReuse/ActiveRecord -- This find is specific to this board update service and won't be reused
        epic_board_position = Boards::EpicBoardPosition.find_or_create_by!(epic_board_id: epic_board_id,
          epic_id: epic.id)
        # rubocop: enable CodeReuse/ActiveRecord
        handle_move_between_ids(epic_board_position)

        epic_board_position.save!
      end

      private

      def fill_missing_positions_before
        before_id = params[:move_between_ids].compact.max
        list_id = params.delete(:list_id)
        board_group = params.delete(:board_group)

        return unless before_id
        # if position for the epic above exists we don't need to create positioning records
        #
        # rubocop: disable CodeReuse/ActiveRecord -- This find is specific to this board update service and won't be reused
        return if Boards::EpicBoardPosition.exists?(epic_board_id: epic_board_id, epic_id: before_id)

        # rubocop: enable CodeReuse/ActiveRecord

        service_params = {
          board_id: epic_board_id,
          list_id: list_id, # we need to have positions only for the current list
          from_id: before_id # we need to have positions only for the epics above
        }

        Boards::Epics::PositionCreateService.new(board_group, current_user, service_params).execute
      end

      override :issuable_for_positioning
      def issuable_for_positioning(id, positioning_scope)
        return unless id

        positioning_scope.find_by_epic_id(id)
      end

      attr_reader :epic, :current_user, :params, :epic_board_id
    end
  end
end

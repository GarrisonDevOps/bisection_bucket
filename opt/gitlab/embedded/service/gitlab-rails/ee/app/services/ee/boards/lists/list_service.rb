# frozen_string_literal: true

module EE
  module Boards
    module Lists
      module ListService
        extend ::Gitlab::Utils::Override

        private

        override :licensed_list_types
        def licensed_list_types(board)
          super + licensed_lists_for(board)
        end

        def licensed_lists_for(board)
          List::LICENSED_LIST_TYPES.filter_map do |list_type|
            next unless board.resource_parent&.feature_available?(:"board_#{list_type}_lists")

            ::List.list_types[list_type]
          end
        end
      end
    end
  end
end

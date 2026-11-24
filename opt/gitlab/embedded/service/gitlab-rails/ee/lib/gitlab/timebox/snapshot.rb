# frozen_string_literal: true

module Gitlab
  module Timebox
    class Snapshot
      attr_reader :date, :item_states

      def initialize(date:)
        @date = date
        @item_states = []
      end

      def add_item(
        item_id:,
        timebox_id:,
        start_state:,
        end_state:,
        parent_id:,
        children_ids:,
        weight:
      )
        @item_states.push({
          item_id: item_id,
          timebox_id: timebox_id,
          start_state: start_state,
          end_state: end_state,
          parent_id: parent_id,
          children_ids: children_ids,
          weight: weight
        })

        self
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Graphql
    module Pagination
      # Gives the same cursors and page info as ArrayConnection, but loads only
      # the window of items it returns. A nil item in the window is left out of
      # the nodes, but keeps its position, so later cursors do not move.
      class WindowedArrayConnection < ArrayConnection
        def cursor_for(item)
          load_nodes
          encode((@window_offset + @window.index(item) + 1).to_s)
        end

        # Taken from the window bounds, not the nodes, so a window of only nil items still
        # moves the next page forward.
        def start_cursor
          load_nodes
          encode((@window_offset + 1).to_s) if @window_count > 0
        end

        def end_cursor
          load_nodes
          encode((@window_offset + @window_count).to_s) if @window_count > 0
        end

        private

        # Mirrors GraphQL::Pagination::ArrayConnection#load_nodes, with indexes instead of slices.
        def load_nodes
          @nodes ||= begin
            length = items.total
            start = (after ? index_from_cursor(after) : 0).clamp(0, length)
            stop = (before ? index_from_cursor(before) - 1 : length).clamp(start, length)
            count = stop - start

            @has_previous_page = last ? count > last : !!after && index_from_cursor(after) > 0
            @has_next_page = before ? index_from_cursor(before) < length + 1 : !!first && count > first

            count = [count, first].min if first
            @window_offset = start + [count - (last || count), 0].max
            count = [count, last].min if last
            @window_count = count

            @window = count > 0 ? items.loader.call(@window_offset, count) : []
            @window.compact
          end
        end
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Graphql
    module Pagination
      # rubocop: disable CodeReuse/ActiveRecord -- reads pages of any relation
      # Reads offset pages without counting `items`. Each read loads one row past the page to learn whether more rows
      # follow it, and a last page reads `reversed_items`, which must return the rows of `items` in the opposite order.
      class BoundedOffsetPageReader
        # `offset` is the number of rows before the page, or nil when only a count of `items` can tell.
        Page = Struct.new(:nodes, :offset, :rows_before, :rows_after, keyword_init: true)

        # @param items [ActiveRecord::Relation]
        # @param reversed_items [Proc] returns the relation in the opposite order, called only by a last page
        def initialize(items, reversed_items)
          @items = items
          @reversed_items = reversed_items
        end

        # @param offset [Integer] number of rows to skip
        # @param size [Integer] maximum number of rows on the page
        # @return [Page]
        def next_page(offset:, size:)
          nodes, rows_after = read(items.offset([offset, 0].max), size)

          Page.new(nodes: nodes, offset: offset, rows_before: offset > 0, rows_after: rows_after)
        end

        # With at most `size` rows after `after_offset`, those rows are the page. With more, the page is the last rows,
        # so the first read is discarded: it costs as much as a `first:` page at that offset.
        #
        # @param size [Integer] maximum number of rows on the page
        # @param after_offset [Integer, nil] number of rows before the `after` cursor
        # @return [Page]
        def last_page(size:, after_offset: nil)
          if after_offset
            page = next_page(offset: after_offset, size: size)
            return page unless page.rows_after
          end

          nodes, rows_before = read(reversed_items.call, size)

          Page.new(nodes: nodes.reverse, offset: (0 unless rows_before), rows_before: rows_before, rows_after: false)
        end

        # @param page [Page] a page from {#last_page}
        # @return [Integer]
        def offset_of(page)
          page.offset || (items.unscope(:order).count(:all) - page.nodes.size)
        end

        private

        attr_reader :items, :reversed_items

        def read(relation, size)
          rows = relation.limit(size + 1).to_a

          [rows.first(size), rows.size > size]
        end
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end

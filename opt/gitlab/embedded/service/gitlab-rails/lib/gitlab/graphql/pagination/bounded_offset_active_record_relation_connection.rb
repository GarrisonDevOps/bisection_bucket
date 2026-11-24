# frozen_string_literal: true

module Gitlab
  module Graphql
    module Pagination
      # Serves `first:` and `last:` pages from {BoundedOffsetPageReader}, leaving `before:`, `first:` with `last:` and
      # limited `items` to graphql-ruby. It overrides its private `limited_nodes`, so a `graphql` upgrade can break it.
      class BoundedOffsetActiveRecordRelationConnection < OffsetActiveRecordRelationConnection
        attr_reader :default_count_limit

        def initialize(items, reversed_items:, default_count_limit:, **kwargs)
          super(items, **kwargs)
          @page_reader = BoundedOffsetPageReader.new(items, reversed_items)
          @default_count_limit = default_count_limit
        end

        def has_previous_page # rubocop:disable Naming/PredicatePrefix -- graphql-ruby connection interface
          bounded_page ? bounded_page.rows_before : super
        end

        def has_next_page # rubocop:disable Naming/PredicatePrefix -- graphql-ruby connection interface
          bounded_page ? bounded_page.rows_after : super
        end

        # Cursors are absolute offsets, so a reversed last page with rows before it counts `items` here.
        def cursor_for(item)
          return super unless bounded_page

          @bounded_page_offset ||= page_reader.offset_of(bounded_page)
          encode((nodes.index(item) + 1 + @bounded_page_offset).to_s)
        end

        private

        attr_reader :page_reader

        def limited_nodes
          # A copy: redaction changes `nodes` in place, and the cursors need the page's row count from before it.
          bounded_page ? bounded_page.nodes.dup : super
        end

        def bounded_page
          return @bounded_page if defined?(@bounded_page)

          @bounded_page =
            case bounded_mode
            when :last then page_reader.last_page(size: last, after_offset: after_offset)
            when :next then page_reader.next_page(offset: after_offset.to_i, size: first)
            end
        end

        def bounded_mode
          return if before || (first && last) || items.limit_value || items.offset_value

          if last then :last
          elsif first then :next
          end
        end
      end
    end
  end
end

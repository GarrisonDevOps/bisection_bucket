# frozen_string_literal: true

module Search
  module Elastic
    module CompositePagination
      # Cursor pagination over an Elasticsearch composite aggregation. Keyset::Paginator cannot
      # be reused: its #build_scope rejects anything that is not an ActiveRecord::Relation.
      #
      # The finder must take (source, params:) and answer #execute with a Page. It is handed
      # `after_key`, `per_page` and `sort` on top of the params given here.
      #
      # A composite aggregation has no `before`, so paging backwards flips the order of every
      # source, pages forward from the cursor, and reverses what comes back.
      class Paginator
        include Enumerable
        include ::Gitlab::Utils::StrongMemoize

        InvalidCursorError = Class.new(StandardError)

        KeysetPaginator = ::Gitlab::Pagination::Keyset::Paginator

        CURSOR_CONVERTER = KeysetPaginator::Base64CursorConverter
        DIRECTION_KEY = :_kd
        FORWARD_DIRECTION = KeysetPaginator::FORWARD_DIRECTION
        BACKWARD_DIRECTION = KeysetPaginator::BACKWARD_DIRECTION
        DIRECTIONS = [FORWARD_DIRECTION, BACKWARD_DIRECTION].freeze

        DEFAULT_PER_PAGE = 20

        def initialize(finder:, source:, params: {}, cursor: nil, per_page: DEFAULT_PER_PAGE)
          @finder = finder
          @source = source
          @params = params
          @per_page = per_page
          @sort = params[:sort].to_s.casecmp?('desc') ? :desc : :asc
          @sort_by = params[:sort_by].presence&.to_s
          @cursor_attributes = decode_cursor(cursor)

          verify_cursor!
        end

        def records
          paginate_backward? ? page.records.reverse : page.records
        end
        strong_memoize_attr :records

        def has_next_page?
          # Having walked backwards to get here, the page we came from is still ahead.
          paginate_forward? ? page.has_next_page? : true
        end

        def has_previous_page?
          return false if at_first_page?

          paginate_backward? ? page.has_next_page? : true
        end

        def cursor_for_next_page
          return unless has_next_page?
          return if last_displayed_key.blank?

          encode_cursor(last_displayed_key, FORWARD_DIRECTION)
        end

        def cursor_for_previous_page
          return unless has_previous_page?
          return if first_displayed_key.blank?

          encode_cursor(first_displayed_key, BACKWARD_DIRECTION)
        end

        delegate :each, :empty?, :any?, :size, to: :records

        private

        attr_reader :finder, :source, :params, :per_page, :sort, :sort_by, :cursor_attributes

        def page
          finder.new(source, params: finder_params).execute
        rescue ::Elasticsearch::Transport::Transport::Errors::BadRequest => error
          # Blank cursor means the error is something else
          raise unless after_key.present?

          # A malformed query looks identical from here, so keep the signal before answering
          # with the friendlier cursor error.
          ::Gitlab::ErrorTracking.log_exception(error)

          raise InvalidCursorError, 'Invalid cursor after_key'
        end
        strong_memoize_attr :page

        def finder_params
          params.merge(after_key: after_key, per_page: per_page, sort: effective_sort)
        end

        # A backward page arrives reversed, so the row shown last is the one the finder saw first.
        def last_displayed_key
          paginate_backward? ? page.first_key : page.last_key
        end

        def first_displayed_key
          paginate_backward? ? page.last_key : page.first_key
        end

        def effective_sort
          return sort unless paginate_backward?

          sort == :desc ? :asc : :desc
        end

        def at_first_page?
          after_key.blank? && paginate_forward?
        end

        def paginate_backward?
          cursor_attributes[DIRECTION_KEY] == BACKWARD_DIRECTION
        end

        def paginate_forward?
          !paginate_backward?
        end

        def after_key
          cursor_attributes[:after_key]
        end

        # Never compact the key: `after` takes null for a missing_bucket source, and dropping
        # one changes its arity, which Elasticsearch rejects.
        def encode_cursor(key, direction)
          CURSOR_CONVERTER.dump(ordering_attributes.merge(after_key: key, DIRECTION_KEY => direction))
        end

        def ordering_attributes
          { sort_by: sort_by, sort: sort }
        end

        def decode_cursor(cursor)
          return { DIRECTION_KEY => FORWARD_DIRECTION }.with_indifferent_access if cursor.blank?

          CURSOR_CONVERTER.parse(cursor)
        rescue ArgumentError, ::JSON::ParserError, TypeError, NoMethodError
          raise InvalidCursorError, 'Invalid cursor'
        end

        # Elasticsearch validates the `after` key's field names and arity, but not its
        # direction: a `desc` cursor replayed under `asc` is accepted and returns nonsense.
        def verify_cursor!
          unless cursor_attributes[DIRECTION_KEY].in?(DIRECTIONS)
            raise InvalidCursorError, "Invalid cursor direction: #{cursor_attributes[DIRECTION_KEY].inspect}"
          end

          raise InvalidCursorError, 'Invalid cursor after_key' unless after_key.nil? || after_key.is_a?(Hash)
          # Only the absent cursor opening the first page carries no key, and it is forward.
          raise InvalidCursorError, 'Invalid cursor after_key' if after_key.blank? && paginate_backward?
          return if after_key.blank?

          return if cursor_attributes[:sort_by].to_s == sort_by.to_s &&
            cursor_attributes[:sort].to_s == sort.to_s

          raise InvalidCursorError, 'The cursor was created for a different ordering'
        end
      end
    end
  end
end

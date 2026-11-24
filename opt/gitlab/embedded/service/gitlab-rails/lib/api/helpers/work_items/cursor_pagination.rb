# frozen_string_literal: true

module API
  module Helpers
    module WorkItems
      # Work item collections page by opaque cursor only, whichever strategy runs underneath. Declares the
      # cursor params and the helpers that page by them, so a collection endpoint mounts only this module.
      module CursorPagination
        extend Grape::API::Helpers

        # Do not `use :pagination` next to this: it would declare a `page` param the keyset pager ignores.
        params :work_items_cursor_pagination_params do
          optional :cursor, type: String, limit: 1024,
            desc: 'Cursor for obtaining the next set of records.', documentation: { example: 'eyJpZCI6IjE0In0' }
          optional :per_page, type: Integer, default: 20, values: 1..100,
            desc: 'Number of items to list per page (maximum 100).', documentation: { example: 20 }
        end

        def check_pagination_param!
          return unless params[:pagination].present? && params[:pagination].to_s != 'keyset'

          render_structured_api_error!(
            { error: 'Explicitly setting offset pagination is not supported.' },
            405
          )
        end

        # Sorts with a keyset form page by keyset; the rest (e.g. popularity, milestone_due) page by offset
        # behind the same cursor, so the client never sees page numbers or totals. Mirrors GraphQL, which
        # also never returns an exact total for this list.
        def paginate_work_items_collection(relation)
          return paginate_with_offset_cursor(relation) unless keyset_supported_for_order?

          paginate_with_keyset_cursor(relation).to_a
        end

        # Pages a keyset-capable collection by cursor, answering a cursor this endpoint cannot use with 400.
        def paginate_with_keyset_cursor(relation, &block)
          validate_cursor_param!(relation.klass)
          params[:pagination] = 'keyset'

          rescue_invalid_keyset_cursor { paginate_with_strategies(relation, &block) }
        end

        # Pages a collection with no keyset form by offset behind the same cursor headers keyset endpoints emit.
        def paginate_with_offset_cursor(scope)
          paginator = Gitlab::Pagination::OffsetCursorPagination.new(
            scope: scope, cursor: params[:cursor], per_page: params[:per_page]
          )

          if paginator.has_next_page? || paginator.has_previous_page?
            Gitlab::Pagination::Keyset::CursorBasedRequestContext
              .new(self)
              .apply_headers(paginator.cursor_for_next_page, paginator.cursor_for_previous_page)
          end

          paginator.records
        rescue Gitlab::Pagination::OffsetCursorPagination::InvalidCursorError => e
          invalid_cursor!(e.message)
        end

        # The shared keyset converter raises ArgumentError, JSON::ParserError or NoMethodError for a cursor it
        # cannot read. Decoding here first keeps the 400 to work item endpoints. `klass` is the paginated
        # model, used to catch values its columns cannot compare with.
        def validate_cursor_param!(klass)
          cursor = params[:cursor]
          return if cursor.blank?

          attributes = Gitlab::Json.safe_parse(Base64.urlsafe_decode64(cursor))
          error = cursor_attributes_error(attributes, klass)
          invalid_cursor!(error) if error
        rescue ArgumentError, JSON::ParserError
          invalid_cursor!('cursor cannot be decoded')
        end

        # RangeError: a numeric string wider than the sort column, which the type check cannot see because the
        # column width is only known when ActiveRecord casts the value while building the query.
        def rescue_invalid_keyset_cursor
          yield
        rescue Gitlab::Pagination::Keyset::InvalidCursorError
          invalid_cursor!('cursor does not match this collection or sort')
        rescue ActiveModel::RangeError
          invalid_cursor!('cursor value is out of range for the sort column')
        end

        private

        # Keyset cursors hold column values: strings, integers that fit a bigint, or nil. Anything else is
        # quoted raw and fails in the database, as does an integer compared with a text, timestamp or date column.
        def cursor_attributes_error(attributes, klass)
          return 'cursor must encode an object' unless attributes.is_a?(Hash)

          unless attributes.values.all? { |value| scalar_cursor_value?(value) }
            return 'cursor values must be strings or integers'
          end

          return unless attributes.any? { |name, value| integer_for_non_numeric_column?(klass, name, value) }

          'cursor value has the wrong type for the sort column'
        end

        def scalar_cursor_value?(value)
          case value
          when nil, String then true
          when Integer then value.bit_length < 64
          else false
          end
        end

        def integer_for_non_numeric_column?(klass, name, value)
          value.is_a?(Integer) && klass.type_for_attribute(name).type.in?(%i[date datetime string text])
        end

        def keyset_supported_for_order?
          ::WorkItem.supported_keyset_orderings[params[:order_by].to_sym]&.include?(params[:sort].to_sym)
        end

        def invalid_cursor!(message)
          render_structured_api_error!({ error: message }, :bad_request)
        end
      end
    end
  end
end

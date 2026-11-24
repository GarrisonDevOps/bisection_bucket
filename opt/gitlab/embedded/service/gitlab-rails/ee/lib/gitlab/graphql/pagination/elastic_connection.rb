# frozen_string_literal: true

module Gitlab
  module Graphql
    module Pagination
      class ElasticConnection < GraphQL::Pagination::Connection # rubocop:disable Search/NamespacedClass -- This is GraphQL related
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::Graphql::ConnectionCollectionMethods
        prepend ::Gitlab::Graphql::ConnectionRedaction

        def nodes
          @nodes ||= last ? last_nodes : first_nodes
        end

        alias_method :ensure_nodes_are_loaded, :nodes

        def has_previous_page?
          if after
            true
          elsif last
            # At this point, we need to load the nodes if they are not already loaded.
            # This method will set the `@has_previous_page` IVar.
            ensure_nodes_are_loaded

            @has_previous_page
          else
            false
          end
        end
        strong_memoize_attr :has_previous_page

        alias_method :has_previous_page, :has_previous_page?

        def has_next_page?
          if before
            true
          elsif first
            # At this point, we need to load the nodes if they are not already loaded.
            # This method will set the `@has_next_page` IVar.
            ensure_nodes_are_loaded

            @has_next_page
          else
            false
          end
        end
        strong_memoize_attr :has_next_page

        alias_method :has_next_page, :has_next_page?

        def cursor_for(node)
          encode(items.cursor_for(node).to_json)
        end

        private

        def last_nodes
          paginated_items = sliced_index.last(limit_value + 1)
          @has_previous_page = paginated_items.length > limit_value

          paginated_items.last(limit_value)
        end

        def first_nodes
          paginated_items = sliced_index.first(limit_value + 1)
          @has_next_page = paginated_items.length > limit_value

          paginated_items.first(limit_value)
        end

        def sliced_index
          if before && after
            raise Gitlab::Graphql::Errors::ArgumentError, "Can only provide either `before` or `after`, not both"
          end

          items.before(*before_cursor) if before_cursor.present?
          items.after(*after_cursor) if after_cursor.present?

          items
        end

        def before_cursor
          return unless before

          ordering_from_encoded_json(before)
        end
        strong_memoize_attr :before_cursor

        def after_cursor
          return unless after

          ordering_from_encoded_json(after)
        end
        strong_memoize_attr :after_cursor

        def ordering_from_encoded_json(cursor)
          Gitlab::Json.safe_parse(decode(cursor))
        rescue JSON::ParserError
          raise Gitlab::Graphql::Errors::ArgumentError, "Please provide a valid cursor"
        end

        def limit_value
          @limit_value ||= [first, last, max_page_size].compact.min
        end
      end
    end
  end
end

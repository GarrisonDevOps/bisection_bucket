# frozen_string_literal: true

module Types
  module Sbom
    class DependencyPathPage < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyPathPage'
      description "Paginated dependency paths for SBOM occurrences"

      field :nodes, [DependencyPathType], null: false,
        description: "List of dependency paths.", hash_key: :paths

      field :edges, [DependencyPathEdge], null: false,
        description: "List of dependency path edges."

      field :page_info, DependencyPathPageInfo, null: false,
        description: "Pagination information for dependency paths."

      def edges
        object[:paths].map do |path_data|
          {
            cursor: cursor_for(path_data),
            node: path_data
          }
        end
      end

      def page_info
        {
          has_next_page: object[:has_next_page],
          has_previous_page: object[:has_previous_page],
          start_cursor: start_cursor,
          end_cursor: end_cursor
        }
      end

      private

      def cursor_for(node)
        Base64.encode64(node[:path].map(&:id).to_json).strip
      end

      def start_cursor
        object[:paths].any? ? cursor_for(object[:paths].first) : nil
      end

      def end_cursor
        object[:paths].any? ? cursor_for(object[:paths].last) : nil
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Zoekt
    module Filters
      MAX_32BIT_INTEGER = (2**32) - 1

      class << self
        def by_substring(pattern:, case_sensitive: nil, file_name: nil, content: nil, context: nil)
          filter = {
            pattern: pattern,
            case_sensitive: case_sensitive,
            file_name: file_name,
            content: content
          }.compact

          with_context(context) do
            { substring: filter }
          end
        end

        def by_repo_ids(ids, context: nil)
          raise ArgumentError, "ids must be an Array, got #{ids.class}" unless ids.is_a?(Array)

          return by_project_ids_through_meta(ids, context: context) if ids.any? { |id| id.to_i > MAX_32BIT_INTEGER }

          with_context(context) do
            { repo_ids: ids.map(&:to_i) }
          end
        end

        def by_project_ids_through_meta(ids, context: nil)
          raise ArgumentError, "ids must be an Array, got #{ids.class}" unless ids.is_a?(Array)
          raise ArgumentError, 'Project IDs cannot be empty' if ids.empty?

          regex_pattern = "^(#{ids.map(&:to_i).join('|')})$"

          with_context(context) do
            by_meta(key: 'project_id', value: regex_pattern)
          end
        end

        def by_regexp(regexp:, case_sensitive: nil, file_name: nil, content: nil, context: nil)
          filter = {
            regexp: regexp,
            case_sensitive: case_sensitive,
            file_name: file_name,
            content: content
          }.compact

          with_context(context) do
            { regexp: filter }
          end
        end

        def and_filters(*filters, context: nil)
          with_context(context) do
            { and: { children: filters } }
          end
        end

        def or_filters(*filters, context: nil)
          with_context(context) do
            { or: { children: filters } }
          end
        end

        def not_filter(filter, context: nil)
          with_context(context) do
            { not: { child: filter } }
          end
        end

        def by_symbol(expr, context: nil)
          with_context(context) do
            { symbol: { expr: expr } }
          end
        end

        def by_meta(key:, value:, context: nil)
          with_context(context) do
            { meta: { key: key.to_s, value: value.to_s } }
          end
        end

        def by_forked(value, context: nil)
          by_meta(key: 'forked', value: value ? 't' : 'f', context: context)
        end

        def by_archived(value, context: nil)
          by_meta(key: 'archived', value: value ? 't' : 'f', context: context)
        end

        def by_query_string(query, context: nil)
          raise ArgumentError, 'Query string cannot be empty' if query.blank?

          query = "case:no #{query}" unless query.match?(/\bcase:(no|yes|auto)\b/)

          with_context(context) do
            { query_string: { query: query } }
          end
        end

        def by_traversal_ids(traversal_ids, context: nil)
          raise ArgumentError, 'Traversal IDs cannot be empty' if traversal_ids.blank?

          by_meta(key: 'traversal_ids', value: "^#{traversal_ids}", context: context)
        end

        def with_context(context)
          result = yield
          result[:_context] = context if result.is_a?(Hash) && context.is_a?(Hash) && context.present?
          result
        end
      end
    end
  end
end

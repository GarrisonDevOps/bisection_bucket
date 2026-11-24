# frozen_string_literal: true

module Search
  module Zoekt
    class SearchRequest
      LANGUAGE_AGGREGATION = 'language'

      def initialize(current_user:, query:, **options)
        @query = query
        @current_user = current_user
        @options = options
        @use_traversal_id_queries = ::Search::Zoekt.feature_available?(
          :traversal_id_search, current_user, group_id: options[:group_id], project_id: options[:project_id]
        )
      end

      def as_json
        payload = {
          version: 2,
          timeout: options.fetch(:timeout, '120s'),
          num_context_lines: options.fetch(:num_context_lines),
          max_file_match_window: options.fetch(:max_file_match_window),
          max_file_match_results: options.fetch(:max_file_match_results),
          max_line_match_window: options.fetch(:max_line_match_window),
          max_line_match_results: options.fetch(:max_line_match_results),
          max_line_match_results_per_file: options.fetch(:max_line_match_results_per_file),
          forward_to: use_traversal_id_queries? ? build_node_queries : build_node_queries_from_targets
        }

        payload[:query] = built_query if top_level_query?

        payload[:aggregations] = [LANGUAGE_AGGREGATION] if options[:aggregation_mode]

        file_match_offset = options.fetch(:file_match_offset, 0)
        payload[:file_match_offset] = file_match_offset if file_match_offset > 0

        payload
      end

      def project_level?
        search_level.project?
      end

      def group_level?
        search_level.group?
      end

      def global_level?
        search_level.global?
      end

      private

      def build_node_queries
        nodes.map do |node|
          entry = { endpoint: node.search_base_url }
          entry[:query] = built_query unless top_level_query?
          entry
        end
      end

      def built_query
        @built_query ||= CodeQueryBuilder.build(query: query, options: {
          current_user: current_user,
          search_level: search_level.as_sym,
          group_id: options[:group_id],
          project_id: options[:project_id],
          filters: options[:filters],
          known_languages: options[:known_languages],
          use_traversal_id_queries: use_traversal_id_queries?
        })
      end

      def build_node_queries_from_targets
        raise ArgumentError, 'No targets specified for the search request' unless options[:targets].present?

        options[:targets].filter_map do |node_id, repo_ids|
          node = ::Search::Zoekt::Node.find_by_id(node_id)
          next if node.nil?

          builder_options = {
            repo_ids: repo_ids,
            use_traversal_id_queries: use_traversal_id_queries?,
            current_user: current_user,
            filters: options[:filters],
            known_languages: options[:known_languages]
          }

          { query: CodeQueryBuilder.build(query: query, options: builder_options), endpoint: node.search_base_url }
        end
      end

      def nodes
        @nodes ||= if search_level.project?
                     project = ::Project.find_by_id(options[:project_id])
                     return [] unless project

                     NodeSelector.for_project(project)
                   elsif search_level.group?
                     group = ::Group.find_by_id(options[:group_id])
                     return [] unless group

                     NodeSelector.for_group(group)
                   else
                     NodeSelector.for_global
                   end
      end

      def use_traversal_id_queries?
        @use_traversal_id_queries
      end

      def top_level_query?
        use_traversal_id_queries? && ::Search::Zoekt.feature_available?(
          :top_level_query, current_user, group_id: options[:group_id], project_id: options[:project_id]
        )
      end

      def search_level
        @search_level ||= ::Search::Level.new(options)
      end

      attr_reader :query, :current_user, :options
    end
  end
end

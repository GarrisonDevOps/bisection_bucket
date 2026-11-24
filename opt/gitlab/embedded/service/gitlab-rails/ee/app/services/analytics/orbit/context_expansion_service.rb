# frozen_string_literal: true

module Analytics
  module Orbit
    # Runs the single named graph query that expands a found, readable entity.
    class ContextExpansionService
      OUTSIDE_GRAPH_SCOPE = 'outside_graph_scope'
      UNSUPPORTED_TYPE = 'expansion_unsupported_type'
      QUERY_NAMES = {
        ContextToken::MERGE_REQUEST => 'context_for_review',
        ContextToken::WORK_ITEM => 'context_for_issue',
        ContextToken::JOB => 'context_for_job'
      }.freeze
      LIMIT = 100
      Renderer = ::Analytics::KnowledgeGraph::QueryRunner::DataRenderer

      def initialize(user, type:, id:, traversal_path:, format:, request_context:, env:)
        @user = user
        @type = type
        @id = id
        @traversal_path = traversal_path
        @format = format
        @request_context = request_context
        @env = env
      end

      def execute
        return error(UNSUPPORTED_TYPE) unless query

        return outcome(error: { code: OUTSIDE_GRAPH_SCOPE }) unless in_graph_scope?

        run
      rescue ::Analytics::KnowledgeGraph::GoverningNamespaceGuard::RequiredError => e
        outcome(error: e.contract.as_json)
      end

      private

      attr_reader :user, :type, :id, :traversal_path, :format, :request_context, :env

      def in_graph_scope?
        authorization_context = ::Analytics::KnowledgeGraph::AuthorizationContext.for(user)
        return false unless authorization_context.traversal_paths_in_scope([traversal_path]).any?

        !authorization_context.admin_user? || root_enabled?
      end

      # Admins see every path, so only the root's Orbit enablement keeps them out of billed empty queries.
      # The path starts with the organization id, followed by the root namespace id.
      def root_enabled?
        root_id = traversal_path.split('/').second.to_i
        enabled_ids = ::Analytics::KnowledgeGraph::EnabledNamespace.root_namespace_ids_for([root_id], limit: 1)
        ::Analytics::Orbit::Billing.reject_gated_root_ids_without_access(enabled_ids).any?
      end

      # The echoed query is the exact payload sent to GKG and is valid for `POST /orbit/query/:name`.
      def query
        name = QUERY_NAMES[type]
        { name: name, parameters: { node_ids: [id], limit: LIMIT } } if name
      end

      def outcome(result)
        result.merge(query: query)
      end

      def run
        params = ::Analytics::KnowledgeGraph::QueryRunner.params_for(
          query: query.to_json,
          query_type: :named,
          user: user,
          format: format,
          request_context: request_context
        )

        response = ::Analytics::KnowledgeGraph::QueryRunner.new(
          params, user: user, env: env, renderer: Renderer.new
        ).execute
        return outcome(result: response.body) if response.is_a?(Renderer::Result) && response.error_code.nil?

        # A client disconnect returns a plain response instead of a result.
        outcome(error: { code: response.try(:error_code) || Renderer::EXECUTION_ERROR })
      end

      def error(code)
        { error: { code: code } }
      end
    end
  end
end

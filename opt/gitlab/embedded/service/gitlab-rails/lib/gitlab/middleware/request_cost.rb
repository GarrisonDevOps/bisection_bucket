# frozen_string_literal: true

module Gitlab
  module Middleware
    # Exposes the root namespace and the per-request Gitaly cost as response
    # headers, for Cloudflare request logs and complexity-based rate limiting.
    class RequestCost
      HEADER_SCORE_GITALY = 'x-gitlab-score-gitaly'
      HEADER_NAMESPACE    = 'x-gitlab-namespace'

      def initialize(app)
        @app = app
      end

      def call(env)
        status, headers, body = @app.call(env)
        add_namespace_header(headers)
        add_cost_header(headers)
        [status, headers, body]
      end

      private

      def add_namespace_header(headers)
        return unless ::Feature.enabled?(:root_namespace_response_header, :current_request, type: :ops)

        namespace_path = root_namespace_path
        headers[HEADER_NAMESPACE] = namespace_path if namespace_path
      end

      def add_cost_header(headers)
        return unless ::Feature.enabled?(:request_cost_headers, :current_request, type: :gitlab_com_derisk)

        gitaly_cost = ::Gitlab::RequestCost.current.get(:gitaly)
        return unless gitaly_cost > 0
        return unless root_namespace_path

        headers[HEADER_SCORE_GITALY] = gitaly_cost.to_s
      end

      def root_namespace_path
        ::Gitlab::ApplicationContext.current_context_attribute(:root_namespace)
      end
    end
  end
end

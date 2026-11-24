# frozen_string_literal: true

module API
  module Orbit
    module QueryResponseHelpers
      def check_orbit_query_rate_limit!
        check_rate_limit!(
          :orbit_query,
          scope: { user: current_user },
          users_allowlist: ::Gitlab::CurrentSettings.orbit_rate_limit_allowlist
        )
      end

      def render_orbit_query!(**query_args)
        render_orbit_response!(::Analytics::KnowledgeGraph::QueryRunner.new(
          ::Analytics::KnowledgeGraph::QueryRunner.params_for(**query_args), user: query_args.fetch(:user), env: env
        ).execute)
      end

      def render_orbit_response!(response)
        apply_etag_or_suppress_rack_etag!(nil)
        status response.status
        content_type response.content_type
        env['api.format'] = :binary
        response.body.is_a?(String) ? body(response.body) : stream(response.body)
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module Search
    module Zoekt
      class Client
        include ::Gitlab::Loggable

        PROXY_SEARCH_PATH = '/webserver/api/v2/search'
        JWT_HEADER = 'Gitlab-Zoekt-Api-Request'

        class << self
          def instance
            @instance ||= new
          end

          delegate :search, to: :instance
        end

        def search(query, num:, search_mode:, current_user: nil, **options)
          start = Time.current
          targets = options[:targets]
          project_id = options[:project_id]
          group_id = options[:group_id]

          if !use_traversal_id_query?(current_user, project_id: project_id, group_id: group_id) && targets.blank?
            log_debug('No targets provided, returning empty response') if debug?
            return Gitlab::Search::Zoekt::Response.empty
          end

          params = ::Search::Zoekt::Params.new(options.merge(limit: num))
          req = ::Search::Zoekt::SearchRequest.new(
            current_user: current_user,
            query: format_query(query, source: options[:source], search_mode: search_mode),
            num_context_lines: params.num_context_lines,
            max_file_match_window: params.max_file_match_window,
            max_file_match_results: params.max_file_match_results,
            max_line_match_window: params.max_line_match_window,
            max_line_match_results: params.max_line_match_results,
            max_line_match_results_per_file: params.max_line_match_results_per_file,
            file_match_offset: params.file_match_offset,
            search_mode: search_mode,
            # A later splat key wins over an earlier explicit one, so a top-level
            # num_context_lines would silently bypass the clamp above.
            **options.except(:num_context_lines)
          )

          if !req.project_level? && !Ability.allowed?(current_user, :read_cross_project)
            log_debug('User does not have permission to search across projects, returning empty response') if debug?
            return Gitlab::Search::Zoekt::Response.empty
          end

          payload = req.as_json

          with_load_balanced_node(**options) do |zkt_node|
            resp = post_request(join_url(zkt_node.search_base_url, PROXY_SEARCH_PATH), payload)
            log_error('Zoekt search failed', status: resp.code, response: resp.body) unless resp.success?
            log_debug('Zoekt AST request', payload: payload) if debug?
            Gitlab::Search::Zoekt::Response.new(parse_response(resp), code: resp.code)
          end
        ensure
          add_request_details(start_time: start, path: PROXY_SEARCH_PATH, body: payload)
        end

        private

        def with_load_balanced_node(**options)
          load_increased = false
          # Rebuilt per request: a memoised balancer keeps a node list that outlives
          # the deletion of a Node row, so a removed node keeps receiving traffic
          # until the process restarts.
          balancer = build_load_balancer
          node = fetch_proxy_node(balancer, **options)
          raise ::Search::Zoekt::Errors::NodeUnavailableError, 'Node can not be found' unless node

          query_weight = determine_query_weight(options)

          balancer.increase_load(node, weight: query_weight)
          load_increased = true

          yield node
        rescue StandardError => e
          log_error(e.message, options)
          raise
        ensure
          balancer.decrease_load(node, weight: query_weight) if load_increased
        end

        def fetch_proxy_node(balancer, **options)
          return node(options[:node_id]) if options[:node_id].present?

          targets = options[:targets]
          if targets.present?
            # Prefer the node with the most projects in targets
            node_id = targets.max_by do |_zkt_node_id, project_ids|
              project_ids.length
            end.first

            node(node_id)
          else
            balancer.pick
          end
        end

        def determine_query_weight(options)
          search_level = ::Search::Level.new(options)

          if search_level.project?
            1
          elsif search_level.group?
            3
          else
            5
          end
        end

        def build_load_balancer
          # Materialised here because LoadBalancer#initialize re-checks emptiness and #pick
          # iterates: an unloaded relation costs an EXISTS per check plus a SELECT.
          nodes = ::Search::Zoekt::Node.for_search.searchable.to_a
          # LoadBalancer raises ArgumentError on an empty set, which escapes the search path's
          # rescues and 500s. Its other caller, ReplicaSelector, still wants that ArgumentError,
          # so translate here rather than in LoadBalancer itself.
          if nodes.empty?
            raise ::Search::Zoekt::Errors::NodeUnavailableError, 'no nodes available for zoekt load balancer'
          end

          ::Search::Zoekt::LoadBalancer.new(nodes)
        end

        def post_request(url, payload = {}, **options)
          defaults = {
            headers: request_headers,
            body: payload.to_json,
            allow_local_requests: true
          }

          log_debug('Zoekt HTTP post request', url: url, payload: payload) if debug?

          ::Gitlab::HTTP.post(url, defaults.merge(options))
        rescue *Gitlab::HTTP::HTTP_ERRORS => e
          logger.error(message: e.message)
          raise ::Search::Zoekt::Errors::ClientConnectionError, e.message
        end

        def request_headers
          {
            'Content-Type' => 'application/json',
            JWT_HEADER => ::Search::Zoekt::JwtAuth.authorization_header
          }
        end

        def node(node_id)
          ::Search::Zoekt::Node.find_by_id(node_id)
        end

        def join_url(base_url, path)
          # We can't use URI.join because it doesn't work properly with something like
          # URI.join('http://example.com/api', 'index') => #<URI::HTTP http://example.com/index>
          url = [base_url, path].join('/')
          url.gsub(%r{(?<!:)/+}, '/') # Remove duplicate slashes
        end

        def parse_response(response)
          # Do not use Gitlab::Json.safe_parse. Zoekt response can contain large amounts of data.
          # Will be fixed as part of https://gitlab.com/groups/gitlab-org/-/work_items/21173.
          json_response = ::Gitlab::Json.parse(response.body).with_indifferent_access
          log_debug('Zoekt HTTP response', data: json_response) if debug?

          json_response
        rescue Gitlab::Json.parser_error => e
          logger.error(message: e.message)
          raise ::Search::Zoekt::Errors::ClientConnectionError, e.message
        end

        def add_request_details(start_time:, path:, body:)
          return unless ::Gitlab::SafeRequestStore.active?

          duration = (Time.current - start_time)

          ::Gitlab::Instrumentation::Zoekt.increment_request_count
          ::Gitlab::Instrumentation::Zoekt.add_duration(duration)

          ::Gitlab::Instrumentation::Zoekt.add_call_details(
            duration: duration,
            method: 'POST',
            path: path,
            body: body
          )
        end

        def logger
          @logger ||= ::Search::Zoekt::Logger.build
        end

        def log_error(message, payload = {})
          logger.error(build_structured_payload(**payload.merge(message: message)))
        end

        def log_debug(message, payload = {})
          logger.debug(build_structured_payload(**payload.merge(message: message)))
        end

        def debug?
          Gitlab.dev_or_test_env? && Gitlab::Utils.to_boolean(ENV['ZOEKT_CLIENT_DEBUG'])
        end

        def format_query(query, source:, search_mode:)
          ::Search::Zoekt::Query.new(query, source: source).formatted_query(search_mode)
        end

        def use_traversal_id_query?(current_user, project_id:, group_id:)
          ::Search::Zoekt.feature_available?(
            :traversal_id_search, current_user, project_id: project_id, group_id: group_id
          )
        end
      end
    end
  end
end

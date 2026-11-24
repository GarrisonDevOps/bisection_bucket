# frozen_string_literal: true

module Gitlab
  module RackAttack
    module LabkitRateLimit
      # Finds the endpoint_id a blocked request would have been served by, in the format
      # of gitlab_sli_rails_request_total. A rack block returns before routing, so nothing
      # else sets one.
      #
      # Walks the Rails routes in the order Rails tries them, and never queries the
      # database: a route whose match only a database lookup can settle (is this path a
      # project, a group or a user?) resolves to nil.
      class EndpointResolver
        include Singleton

        # Their path format check runs without the lookup, so a path that fails it is
        # skipped rather than left unresolved.
        PATH_CONSTRAINTS = [
          ::Projects::ProjectUrlConstraint,
          ::Namespaces::GroupUrlConstraint,
          ::Users::UserUrlConstraint
        ].freeze

        # Built at boot from RequestsRackMiddleware.initialize_slis!, so a block never
        # builds it. Singleton locks the first .instance call.
        def initialize
          @grape_matchers = ::Gitlab::RequestEndpoints.all_api_endpoints
            .group_by(&:request_method)
            .transform_values { |routes| build_grape_matcher(routes) }
        end

        # @param env [Hash] the Rack env, with a normalized PATH_INFO. Only the method,
        #   path and Accept header are read, so the body is never parsed.
        # @return [String, nil] the endpoint_id, or nil when no route resolves without a
        #   database lookup
        def endpoint_id(env)
          request = ::ActionDispatch::Request.new(routing_env(env))
          endpoint_id = nil

          ::Rails.application.routes.router.recognize(request) do |route, params|
            app = route.app

            if grape_mount?(app)
              served, endpoint_id = grape_match(request.request_method, request.path_info)
              # Grape passes a path it has no route for back to Rails, so keep walking.
              next unless served

              break
            end

            # Redirects and other mounted apps have no endpoint_id.
            break unless app.dispatcher?

            request.path_parameters = params
            match = constraints_match(app, request)
            next if match == false

            endpoint_id = controller_endpoint_id(params) if match
            break
          end

          endpoint_id
        end

        private

        # No GitLab route has a host or subdomain constraint, so the host is left out.
        def routing_env(env)
          {
            'REQUEST_METHOD' => env['REQUEST_METHOD'],
            'PATH_INFO' => env['PATH_INFO'],
            'SCRIPT_NAME' => '',
            'QUERY_STRING' => '',
            'HTTP_ACCEPT' => env['HTTP_ACCEPT'],
            'rack.input' => StringIO.new
          }
        end

        def grape_mount?(app)
          app.respond_to?(:app) && app.app == ::API::API
        end

        # true when the route matches, false when it does not, nil when only a database
        # lookup or an unknown constraint class could tell. Mapper::Constraints wraps a
        # dispatcher only when it has constraint objects or lambdas.
        def constraints_match(app, request)
          return true unless app.respond_to?(:constraints)

          results = app.constraints.map { |constraint| constraint_match(constraint, request) }
          return false if results.include?(false)

          results.all?(true) || nil
        end

        def constraint_match(constraint, request)
          case constraint
          when Proc
            # Every route lambda takes only the request. The spec that calls each one fails if not.
            constraint.call(request) ? true : false
          when *PATH_CONSTRAINTS
            constraint.matches?(request, existence_check: false) ? nil : false
          end
        rescue StandardError
          # A lambda that reads more than the request we pass (a session, warden) cannot tell.
          nil
        end

        # Same id as Gitlab::EndpointAttributes#endpoint_id_for_action.
        def controller_endpoint_id(params)
          "#{params[:controller].camelize}Controller##{params[:action]}"
        end

        # The order Grape::Router#transaction uses: the method's routes, then for OPTIONS
        # the generated handler of any route on the path (no endpoint_id), then the :any
        # routes. HEAD is served by a HEAD copy of the GET route.
        # Returns whether Grape serves the path, and the endpoint_id it would record.
        def grape_match(method, path)
          route = grape_route(method == 'HEAD' ? 'GET' : method, path)
          return [true, "#{method} #{route.origin}"] if route
          return [true, nil] if method == 'OPTIONS' && grape_path_known?(path)

          # The only :any routes are the catch-alls. They skip the context push, so an
          # unblocked request records unknown.
          [grape_route('*', path).present?, nil]
        end

        def grape_path_known?(path)
          @grape_matchers.except('*').each_value.any? { |matcher| matcher[:regexp].match?(path) }
        end

        def grape_route(method, path)
          matcher = @grape_matchers[method]
          match = matcher && matcher[:regexp].match(path)
          return unless match

          matcher[:routes][matcher[:captures].index { |capture| match[capture] }]
        end

        # One combined regex per HTTP method, the way Grape::Router#compile! builds its own.
        # Not via Route#to_regexp: that sets the route's index, which Grape's router reads.
        def build_grape_matcher(routes)
          captures = Array.new(routes.size) { |index| "_#{index}" }
          regexps = routes.each_with_index.map do |route, index|
            Regexp.new("(?<#{captures[index]}>#{route.pattern.to_regexp})")
          end

          {
            regexp: Regexp.union(regexps),
            captures: captures,
            routes: routes
          }
        end
      end
    end
  end
end

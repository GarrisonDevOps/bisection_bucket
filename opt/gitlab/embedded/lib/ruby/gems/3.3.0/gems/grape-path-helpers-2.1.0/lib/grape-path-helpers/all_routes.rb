# frozen_string_literal: true

module GrapePathHelpers
  # methods to extend Grape::API's behavior so it can get a
  # list of routes from all APIs and decorate them with
  # the DecoratedRoute class
  module AllRoutes
    def decorated_routes_by_helper_name # rubocop:disable Metrics/AbcSize
      return @decorated_routes_by_helper_name if @decorated_routes_by_helper_name

      routes = {}

      all_routes
        .map { |r| DecoratedRoute.new(r) }
        .sort_by { |r| -r.dynamic_path_segments.count }
        .each do |route|
          route.helper_names.each do |helper_name|
            key = helper_name.to_sym

            routes[key] ||= []
            routes[key] << route
          end
        end

      @decorated_routes_by_helper_name = routes
    end

    def all_routes
      routes = descendants.flat_map { |d| d.endpoints.flat_map(&:routes) }
      routes.uniq { |r| r.options.merge(path: r.path) }
    end
  end
end

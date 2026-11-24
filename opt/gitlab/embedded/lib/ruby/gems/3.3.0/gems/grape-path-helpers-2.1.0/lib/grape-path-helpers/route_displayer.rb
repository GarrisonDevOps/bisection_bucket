# frozen_string_literal: true

module GrapePathHelpers
  # class for displaying the path, helper method name,
  # and required arguments for every Grape::Route.
  class RouteDisplayer
    def route_attributes
      Grape::API::Instance
        .decorated_routes_by_helper_name
        .values
        .flatten
        .uniq
        .map do |route|
        {
          route_path: route.route_path,
          route_method: route.route_method,
          helper_names: route.helper_names,
          helper_arguments: route.helper_arguments
        }
      end
    end

    def display
      puts("== GRAPE ROUTE HELPERS ==\n\n")
      route_attributes.each do |attributes|
        puts("Verb: #{attributes[:route_method]}")
        puts("Path: #{attributes[:route_path]}")
        puts("Helper Method: #{attributes[:helper_names].join(', ')}")
        puts("Arguments: #{attributes[:helper_arguments].join(', ')}")
        puts("\n")
      end
    end
  end
end

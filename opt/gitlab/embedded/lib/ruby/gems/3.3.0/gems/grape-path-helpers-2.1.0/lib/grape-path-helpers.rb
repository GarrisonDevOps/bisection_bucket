# frozen_string_literal: true

require 'grape'
require 'active_support'
require 'active_support/core_ext/class'

require 'grape-path-helpers/decorated_route'
require 'grape-path-helpers/named_route_matcher'
require 'grape-path-helpers/all_routes'
require 'grape-path-helpers/route_displayer'

# Load the Grape route helper for Rails
module GrapePathHelpers
  require 'grape-path-helpers/railtie' if defined?(Rails)
end

Grape::API::Instance.extend GrapePathHelpers::AllRoutes
Grape::Endpoint.prepend GrapePathHelpers::NamedRouteMatcher

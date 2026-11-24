# frozen_string_literal: true

# Rails computes `action_methods` for every controller at eager load by converting all of its
# public instance methods to Strings and building a Set, then subtracting the route helper names,
# converted to Strings again. Our controllers include the url helpers, so that is ~8800 methods per
# controller, ~8100 of them route helpers, times 684 controllers: 5.4 s of the production boot.
#
# Fixed upstream for Rails 8.2 by subtracting on Symbols first and converting only the remaining
# action names: https://github.com/rails/rails/pull/59464. This is that change for the Rails 8.0
# and 8.1 implementations of `action_methods`. Rails 8.1 no longer adds back the internal methods
# defined on the controller class itself.
# https://github.com/rails/rails/blob/v8.0.5.1/actionpack/lib/abstract_controller/base.rb#L93-L103
# https://github.com/rails/rails/blob/v8.1.4/actionpack/lib/abstract_controller/base.rb#L93-L101
# https://github.com/rails/rails/blob/v8.1.4/actionpack/lib/abstract_controller/url_for.rb#L28-L34
if Rails.gem_version >= Gem::Version.new('8.2')
  raise 'Rails 8.2 includes https://github.com/rails/rails/pull/59464. Remove this patch.'
end

module ActionControllerActionMethodsPatch
  module NamedRouteCollection
    def helper_name_symbols
      @path_helpers.to_a + @url_helpers.to_a # rubocop:disable Gitlab/ModuleWithInstanceVariables -- included into NamedRouteCollection
    end
  end

  module ClassMethods
    def action_methods
      @action_methods ||= begin
        methods = public_instance_methods(true) - internal_methods
        methods.concat(public_instance_methods(false)) if Rails.gem_version < Gem::Version.new('8.1')
        methods -= _routes.named_routes.helper_name_symbols if _routes
        methods.map!(&:name)
        methods.to_set
      end
    end
  end
end

ActionDispatch::Routing::RouteSet::NamedRouteCollection.include(ActionControllerActionMethodsPatch::NamedRouteCollection)

ActiveSupport.on_load(:action_controller_base) do
  singleton_class.prepend(ActionControllerActionMethodsPatch::ClassMethods)
end

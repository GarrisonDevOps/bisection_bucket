# frozen_string_literal: true

# The router's transition table ignores regexp lookarounds, such as those in Gitlab::PathRegex, so it can
# return routes whose path does not match, and Rails then raises "undefined method 'names' for nil".
# See https://github.com/rails/rails/issues/47244
module ActionDispatch
  module Journey
    module FilterRoutesPatch
      private

      def filter_routes(path)
        super.select { |route| route.path.match?(path) }
      end
    end

    raise 'Router#filter_routes is gone, revisit this patch' unless Router.private_method_defined?(:filter_routes)

    Router.prepend(FilterRoutesPatch)
  end
end

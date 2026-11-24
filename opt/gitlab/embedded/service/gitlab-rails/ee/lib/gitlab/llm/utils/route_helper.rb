# frozen_string_literal: true

module Gitlab
  module Llm
    module Utils
      class RouteHelper
        include ::Gitlab::Utils::StrongMemoize

        def initialize(url)
          @url = url
        end

        def exists?
          !!route
        end

        def project
          Project.find_by_full_path("#{route&.[](:namespace_id)}/#{route&.[](:project_id)}")
        end

        def namespace
          Namespace.find_by_full_path(route&.[](:namespace_id))
        end

        def controller
          route&.[](:controller)
        end

        def id
          route&.[](:id)&.to_i
        end

        def action
          route&.[](:action)
        end

        private

        attr_reader :url

        def route
          uri = Gitlab::Utils.parse_url(url)
          return unless uri

          path = uri.path.delete_prefix('/')
          Rails.application.routes.recognize_path(path)
        rescue ActionController::RoutingError
          nil
        end
        strong_memoize_attr :route
      end
    end
  end
end

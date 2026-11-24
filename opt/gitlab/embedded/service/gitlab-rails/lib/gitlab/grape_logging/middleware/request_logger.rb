# frozen_string_literal: true

module Gitlab
  module GrapeLogging
    module Middleware
      class RequestLogger < ::GrapeLogging::Middleware::RequestLogger
        SKIP_ENV_KEY = 'gitlab.grape_logging.skip_request_logging'

        def call!(env)
          return @app.call(env) if env[SKIP_ENV_KEY]

          super
        end
      end
    end
  end
end

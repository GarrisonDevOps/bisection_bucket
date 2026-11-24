# frozen_string_literal: true

module Gitlab
  class Experiment
    class Middleware
      def self.redirect(id, url)
        raise Error, 'no url to redirect to' if url.blank?

        experiment = Gitlab::Experiment.from_param(id)
        [303, { 'Location' => experiment.process_redirect_url(url) || raise(Error, 'not redirecting') }, []]
      end

      def initialize(app, base_path)
        @app = app
        @matcher = %r{^#{base_path}/(?<id>.+)}
      end

      def call(env)
        return @app.call(env) if env['REQUEST_METHOD'] != 'GET' || (match = @matcher.match(env['PATH_INFO'])).nil?

        Middleware.redirect(match[:id], env['QUERY_STRING'])
      rescue Error
        @app.call(env)
      end
    end
  end
end

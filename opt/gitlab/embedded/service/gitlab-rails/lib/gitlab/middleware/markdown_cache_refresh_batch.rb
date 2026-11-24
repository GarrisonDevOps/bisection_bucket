# frozen_string_literal: true

module Gitlab
  module Middleware
    class MarkdownCacheRefreshBatch
      def initialize(app)
        @app = app
      end

      def call(env)
        ::Gitlab::MarkdownCache::RefreshBatch.within { @app.call(env) }
      end
    end
  end
end

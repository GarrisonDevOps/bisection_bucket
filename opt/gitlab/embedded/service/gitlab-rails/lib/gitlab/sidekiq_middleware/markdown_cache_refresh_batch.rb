# frozen_string_literal: true

module Gitlab
  module SidekiqMiddleware
    class MarkdownCacheRefreshBatch
      def call(_worker, _job, _queue)
        ::Gitlab::MarkdownCache::RefreshBatch.within { yield }
      end
    end
  end
end

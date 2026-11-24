# frozen_string_literal: true

Gitlab::Application.configure do |config|
  config.middleware.insert_after(RequestStore::Middleware, Gitlab::Middleware::MarkdownCacheRefreshBatch)
end

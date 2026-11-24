# frozen_string_literal: true

Rails.application.configure do |config|
  # Gitlab::Middleware::RequestContext removes the context pushed by controllers and the API when it returns.
  config.middleware.insert_after Gitlab::Middleware::RequestContext, Gitlab::Middleware::RequestCost
end

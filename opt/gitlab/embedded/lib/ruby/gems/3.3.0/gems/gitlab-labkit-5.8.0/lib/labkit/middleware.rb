# frozen_string_literal: true

module Labkit
  # Adds middlewares for using in rack and sidekiq
  module Middleware
    autoload :Rack, "labkit/middleware/rack"
    autoload :Sidekiq, "labkit/middleware/sidekiq"
  end
end

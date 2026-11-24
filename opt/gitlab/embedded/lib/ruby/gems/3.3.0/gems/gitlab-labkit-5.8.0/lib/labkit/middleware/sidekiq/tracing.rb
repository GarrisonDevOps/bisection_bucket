# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      # Sidekiq provides classes for instrumenting Sidekiq client and server
      # functionality
      module Tracing
        autoload :Client, "labkit/middleware/sidekiq/tracing/client"
        autoload :Server, "labkit/middleware/sidekiq/tracing/server"
        autoload :SidekiqCommon, "labkit/middleware/sidekiq/tracing/sidekiq_common"
      end
    end
  end
end

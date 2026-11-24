# frozen_string_literal: true

module Labkit
  module Middleware
    module Sidekiq
      # This module contains all the sidekiq middleware regarding application
      # context
      module Context
        autoload :Client, "labkit/middleware/sidekiq/context/client"
        autoload :Server, "labkit/middleware/sidekiq/context/server"
      end
    end
  end
end

# frozen_string_literal: true

module Search
  module Zoekt
    module Errors
      BaseError = Class.new(StandardError)
      ClientConnectionError = Class.new(BaseError)
      # No node is available to serve the search, so no request is made. Distinct from
      # ClientConnectionError, which means a node was picked and the request to it failed.
      NodeUnavailableError = Class.new(BaseError)
    end
  end
end

# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    BusyError = Class.new(Gitlab::SidekiqMiddleware::RetryError)
  end
end

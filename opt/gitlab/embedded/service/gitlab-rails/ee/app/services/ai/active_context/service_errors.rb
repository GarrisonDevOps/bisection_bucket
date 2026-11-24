# frozen_string_literal: true

module Ai
  module ActiveContext
    module ServiceErrors
      Error = Class.new(StandardError)
      InvalidError = Class.new(Error)
      UpdateFailed = Class.new(Error)
    end
  end
end

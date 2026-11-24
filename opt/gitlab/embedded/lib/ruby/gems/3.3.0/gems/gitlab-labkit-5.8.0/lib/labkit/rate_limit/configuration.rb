# frozen_string_literal: true

module Labkit
  module RateLimit
    class Configuration
      attr_accessor :redis, :logger
    end
  end
end

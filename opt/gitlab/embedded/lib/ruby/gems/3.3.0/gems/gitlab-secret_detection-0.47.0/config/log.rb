# frozen_string_literal: true

require 'grpc'
require 'logger'

# SD_ENV env var is used to determine which environment the
# server is running. This var is defined in `.runway/env-<env>.yml` files.
def local_env?
  ENV.fetch('SD_ENV', 'localhost') == 'localhost'
end

module SDLogger
  LOGGER = Logger.new $stderr, level: local_env? ? Logger::DEBUG : Logger::INFO

  def logger
    LOGGER
  end
end

# Configure logger for GRPC
module GRPC
  extend SDLogger
end

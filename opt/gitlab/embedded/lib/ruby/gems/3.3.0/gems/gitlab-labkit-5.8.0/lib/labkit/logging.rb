# frozen_string_literal: true

module Labkit
  # Logging provides functionality for logging, such as
  # sanitization
  module Logging
    autoload :GRPC, "labkit/logging/grpc"
    autoload :Sanitizer, "labkit/logging/sanitizer"
    autoload :JsonLogger, "labkit/logging/json_logger"

    # Eagerly load FieldValidator in non-production environments
    # This ensures injection happens before JsonLogger instances are created
    require "labkit/logging/field_validator" unless ENV['RAILS_ENV'] == 'production'
  end
end

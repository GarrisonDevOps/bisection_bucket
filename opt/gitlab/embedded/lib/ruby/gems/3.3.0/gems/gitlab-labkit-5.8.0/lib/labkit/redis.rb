# frozen_string_literal: true

module Labkit
  # Redis utilities shared across Labkit (script execution, key helpers, etc.).
  module Redis
    autoload :Script, "labkit/redis/script"
  end
end

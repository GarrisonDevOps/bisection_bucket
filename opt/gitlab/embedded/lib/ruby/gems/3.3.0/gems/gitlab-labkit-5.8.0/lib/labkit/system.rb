# frozen_string_literal: true

module Labkit
  # A helper class to store system-related methods used in metrics, tracing, and logging
  module System
    # Returns the current monotonic clock time as seconds with microseconds precision.
    #
    # Returns the time as a Float.
    def self.monotonic_time
      Process.clock_gettime(Process::CLOCK_MONOTONIC, :float_second)
    end
  end
end

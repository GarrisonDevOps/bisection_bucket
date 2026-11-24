# frozen_string_literal: true

module Mcp
  module Tools
    # Fails a read once more than max_bytes have been read through it. Zip::File.open_buffer
    # locates and sizes the central directory from fields inside the archive, so counting what
    # it actually reads bounds the load no matter which of those fields a crafted archive fakes.
    class ByteLimitedIo < SimpleDelegator
      LimitExceeded = Class.new(StandardError)

      def initialize(io, max_bytes:)
        super(io)
        @remaining = max_bytes
      end

      def read(...)
        data = __getobj__.read(...)
        return data if @remaining.nil? || data.nil?

        @remaining -= data.bytesize
        raise LimitExceeded if @remaining < 0

        data
      end

      def remove_limit!
        @remaining = nil
      end
    end
  end
end

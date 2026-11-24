# frozen_string_literal: true

module Bitbucket
  module Representation
    class Base
      attr_reader :raw

      delegate :present?, to: :raw

      def self.decorate(entries)
        entries.map { |entry| new(entry) }
      end

      def initialize(raw)
        unless raw.is_a?(Hash)
          raise Bitbucket::Error::InvalidResponse,
            "Expected Hash response, got #{raw.class.name}: #{raw.to_s.truncate(200)}"
        end

        @raw = raw
      end
    end
  end
end

# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    # Value class to encapsulate schemaVer related logic
    class SchemaVer
      VALID_SCHEMA_FORMAT = /\d+\.\d+\.\d+/

      class InvalidSchemaVersion < StandardError; end

      include Comparable

      def self.new!(version, fallback: true)
        return SecurityReportSchemas.supported_versions.last if version.blank?

        raise InvalidSchemaVersion, version unless version.match?(VALID_SCHEMA_FORMAT)

        instance = new(version)

        fallback ? instance.itself_or_fallback : instance
      end

      attr_reader :version

      def initialize(version)
        @version = version[VALID_SCHEMA_FORMAT]
      end

      def itself_or_fallback
        supported? ? self : (fallback || self)
      end

      def supported?
        supported_versions.include?(self)
      end

      def deprecated?
        deprecated_versions.include?(self)
      end

      def fallback?
        @fallback_to.present?
      end

      attr_accessor :fallback_to

      # The below public methods are commonly used by the Ruby's standard library

      delegate :hash, to: :version

      def eql?(other)
        other.is_a?(self.class) && version == other.version
      end

      def <=>(other)
        segments <=> other.segments
      end

      def to_s
        version
      end

      # Enables implicit conversion to string
      alias_method :to_str, :to_s

      protected

      def segments
        @segments ||= version.split(".").map(&:to_i)
      end

      def compatible?(other)
        model == other.model &&
          revision == other.revision &&
          addition > other.addition
      end

      def model
        segments[0]
      end

      def revision
        segments[1]
      end

      def addition
        segments[2]
      end

      def as_fallback_to!(primary)
        dup.tap { |duplicate| duplicate.fallback_to = primary }
      end

      private

      delegate :supported_versions, :deprecated_versions, to: SecurityReportSchemas, private: true

      def fallback
        supported_versions.select { |version| compatible?(version) }
                          .max
                          &.as_fallback_to!(self)
      end
    end
  end
end

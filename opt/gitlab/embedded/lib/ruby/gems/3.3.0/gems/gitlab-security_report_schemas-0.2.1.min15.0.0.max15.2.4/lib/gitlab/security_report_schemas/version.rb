# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    # Represents the version of the gem
    class Version
      VERSION_SPEC = "%<gem_version>s.min%<min_schema>s.max%<max_schema>s"
      GEM_VERSION = "0.2.1"
      MISSING_SCHEMA_VERSION = "0.0.0"

      class << self
        def to_s
          format(VERSION_SPEC,
                 gem_version: GEM_VERSION,
                 min_schema: min_schema,
                 max_schema: max_schema)
        end

        def min_schema
          SecurityReportSchemas.supported_versions.first || MISSING_SCHEMA_VERSION
        end

        def max_schema
          SecurityReportSchemas.supported_versions.last || MISSING_SCHEMA_VERSION
        end
      end
    end
  end
end

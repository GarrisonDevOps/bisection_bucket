# frozen_string_literal: true

module Types
  module Sbom
    class SourceTypeEnum < BaseEnum
      graphql_name 'SbomSourceType'
      description 'Values for sbom source types'

      ::Sbom::Source.source_types.each_key do |source_type|
        value source_type.to_s.upcase,
          description: "Source Type: #{source_type}.",
          value: source_type
      end

      value "NIL_SOURCE",
        description: "Enum source nil.",
        value: "nil_source"
    end
  end
end

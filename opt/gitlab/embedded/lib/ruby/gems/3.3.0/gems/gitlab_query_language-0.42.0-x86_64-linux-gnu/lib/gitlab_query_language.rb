# frozen_string_literal: true

require "json"
require_relative "gitlab_query_language/version"

# Load the appropriate version-specific native extension
begin
  ruby_version = /(\d+\.\d+)/.match(RUBY_VERSION)
  require_relative "gitlab_query_language/#{ruby_version}/gitlab_query_language"
rescue LoadError
  require_relative "gitlab_query_language/gitlab_query_language"
end

module Glql
  Error = Class.new(StandardError)

  class << self
    def compile(query, context)
      result_json = compile_rs(query, context.to_json)
      JSON.parse(result_json)
    end

    def transform(data, context)
      result_json = transform_rs(data.to_json, context.to_json)
      JSON.parse(result_json)
    end

    # The GLQL schema: every data source with its filter, display and sort
    # fields, plus the operator, value kind, reference type and function
    # vocabularies.
    #
    # `version` is this gem's version rather than a field of the document, so it
    # cannot disagree with the artifact it shipped in. Merged last so a `version`
    # in the document could not override it.
    def schema
      @schema ||= freeze_recursively(JSON.parse(schema_rs).merge("version" => VERSION))
    end

    private

    # Freezes in place, at every level.
    #
    # `Hash#freeze` is shallow, and the memo above is shared for the life of the
    # process: without this a caller mutating `schema["sources"]` would corrupt
    # the document for every later reader.
    def freeze_recursively(value)
      case value
      when Hash then value.each_value { |item| freeze_recursively(item) }
      when Array then value.each { |item| freeze_recursively(item) }
      end

      value.freeze
    end
  end
end

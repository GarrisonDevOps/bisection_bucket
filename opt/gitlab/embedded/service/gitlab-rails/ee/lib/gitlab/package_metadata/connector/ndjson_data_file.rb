# frozen_string_literal: true

require 'csv'

module Gitlab
  module PackageMetadata
    module Connector
      class NdjsonDataFile < BaseDataFile
        Error = Class.new(StandardError)

        def parse(text)
          ::Gitlab::Json.parse(text.force_encoding('UTF-8'))
        rescue JSON::ParserError => e
          Gitlab::ErrorTracking.track_exception(
            Error.new(
              "json parsing error on '#{text}'"),
            errors: e.message
          )

          nil
        end

        def self.file_suffix
          'ndjson'
        end
      end
    end
  end
end

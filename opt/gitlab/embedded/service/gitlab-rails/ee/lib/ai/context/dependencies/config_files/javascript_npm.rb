# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class JavascriptNpm < Base
          def self.file_name_glob
            'package.json'
          end

          def self.lang_name
            'JavaScript'
          end

          private

          ### Example format:
          #
          # "dependencies": {
          #   "all-the-cities": "3.1.0",
          #   "argon2": "0.41.1",
          #   "countly-request": "file:api/utils/countly-request"
          # },
          # "devDependencies": {
          #   "apidoc": "^1.0.1",
          #   "apidoc-template": "^0.0.2"
          # },
          #
          def extract_libs
            parsed = ::Gitlab::Json.safe_parse(content)

            %w[dependencies devDependencies].flat_map do |key|
              dig_in(parsed, key).try(:map) do |name, version|
                # Skip dependency if the version is a local filepath
                next if version&.include?('/')

                Lib.new(name: name, version: version)
              end
            end.compact
          rescue JSON::ParserError
            raise ParsingErrors::DeserializationException, 'content is not valid JSON'
          end
        end
      end
    end
  end
end

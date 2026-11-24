# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class JavascriptNpmLock < Base
          NAME_PREFIX = 'node_modules/'
          PUBLIC_REGISTRY_PREFIX = 'https://registry.npmjs.org/'

          def self.file_name_glob
            'package-lock.json'
          end

          def self.lang_name
            'JavaScript'
          end

          private

          ### The first package is always an empty string representing the project itself
          ### Example format:
          #
          # "packages": {
          #   "": {
          #     "name": "countly-server",
          #     "version": "24.5.0"
          #   },
          #   "api/utils/countly-root": {
          #     "version": "0.1.0"
          #   },
          #   "node_modules/@babel/core/node_modules/convert-source-map": {
          #     "version": "2.0.0",
          #     "resolved": "https://registry.npmjs.org/...",
          #     "integrity": "sha512-...",
          #     "dev": true,
          #     "license": "MIT"
          #   }
          # }
          #
          def extract_libs
            parsed = ::Gitlab::Json.safe_parse(content)

            dig_in(parsed, 'packages').try(:filter_map) do |name, dep|
              next if name.empty?
              next unless dig_in(dep, 'resolved')&.start_with?(PUBLIC_REGISTRY_PREFIX)

              name = name.delete_prefix(NAME_PREFIX).delete('@')
              version = dig_in(dep, 'version')

              Lib.new(name: name, version: version)
            end
          rescue JSON::ParserError
            raise ParsingErrors::DeserializationException, 'content is not valid JSON'
          end
        end
      end
    end
  end
end

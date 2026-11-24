# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class CppVcpkg < Base
          REVISION_REGEX = /#.*$/

          def self.file_name_glob
            'vcpkg.json'
          end

          def self.lang_name
            'C++'
          end

          private

          ### Example format:
          #
          # {
          #   "dependencies": [
          #     "cxxopts",
          #     "fmt@8.0.1#rev1",
          #     { "name": "boost", "version>=": "1.7.6" },
          #     { "name": "zlib" }
          #   ],
          #   "test-dependencies": [
          #     "poco@1.12.4",
          #     { "name": "sqlite3", "version>=": "3.37.0#4" }
          #   ]
          # }
          #
          def extract_libs
            parsed = Gitlab::Json.safe_parse(content)
            deps = Array.wrap(dig_in(parsed, 'dependencies')) + Array.wrap(dig_in(parsed, 'test-dependencies'))

            deps.map do |dep|
              if dep.is_a?(String)
                name, version = dep.split('@')
              else
                name = dig_in(dep, 'name')
                version = dig_in(dep, 'version>=')
              end

              version&.gsub!(REVISION_REGEX, '')

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

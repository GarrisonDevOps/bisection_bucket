# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class PhpComposerLock < Base
          def self.file_name_glob
            'composer.lock'
          end

          def self.lang_name
            'PHP'
          end

          private

          ### Example format:
          #
          # "packages": [
          #   {
          #     "name": "composer/ca-bundle",
          #     "version": "1.5.1",
          #     "source": {
          #         "type": "git",
          #         "url": "https://github.com/composer/ca-bundle.git",
          #         "reference": "063d9aa8696582f5a41dffbbaf3c81024f0a604a"
          #     },
          #   }
          #   { ... }
          # ]
          #
          def extract_libs
            parsed = ::Gitlab::Json.safe_parse(content)

            dig_in(parsed, 'packages').try(:map) do |dep|
              Lib.new(name: dig_in(dep, 'name'), version: dig_in(dep, 'version'))
            end
          rescue JSON::ParserError
            raise ParsingErrors::DeserializationException, 'content is not valid JSON'
          end
        end
      end
    end
  end
end

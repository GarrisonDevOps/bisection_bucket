# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class PhpComposer < Base
          def self.file_name_glob
            'composer.json'
          end

          def self.lang_name
            'PHP'
          end

          private

          ### Example format:
          #
          # {
          #   { ... },
          #   "require": {
          #     "php": "^7.2.5 || ^8.0",
          #     "composer/ca-bundle": "^1.5"
          #   },
          #   "require-dev": {
          #     "symfony/phpunit-bridge": "^6.4.3 || ^7.0.1",
          #     "phpstan/phpstan": "^1.11.8"
          #   },
          #   { ... }
          # }
          #
          def extract_libs
            parsed = ::Gitlab::Json.safe_parse(content)

            %w[require require-dev].flat_map do |key|
              dig_in(parsed, key).try(:map) do |name, version|
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

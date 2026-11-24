# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class PythonPoetryLock < Base
          def self.file_name_glob
            'poetry.lock'
          end

          def self.lang_name
            'Python'
          end

          private

          ### Example format:
          #
          # [[package]]
          # name = "anthropic"
          # version = "0.28.1"
          # description = "The official Python library for the anthropic API"
          # optional = false
          # python-versions = ">=3.7"
          # files = [
          #     {file = "anthropic-0.28.1-py3-none-any.whl", hash = "..."},
          #     {file = "anthropic-0.28.1.tar.gz", hash = "..."},
          # ]
          #
          def extract_libs
            parsed = Gitlab::Utils::TomlParser.safe_parse(content)

            dig_in(parsed, 'package').try(:map) do |dep|
              Lib.new(name: dig_in(dep, 'name'), version: dig_in(dep, 'version'))
            end
          rescue Gitlab::Utils::TomlParser::ParseError => e
            raise ParsingErrors::DeserializationException, e.message
          end
        end
      end
    end
  end
end

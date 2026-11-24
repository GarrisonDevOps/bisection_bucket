# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class PythonPoetry < Base
          START_ANY_SECTION_REGEX = /^\[/
          START_DEPS_SECTION_REGEX = /^\[tool\.poetry\..*dependencies\]/
          NAME_VERSION_REGEX = /^(?<name>[^\s=]+)(?:\s=\s"(?<version>[^"]+)")?/
          LONG_FORM_NAME_VERSION_REGEX = /^(?<name>[^\s=]+).*?\sversion\s=\s"(?<version>[^"]+)"/
          COMMENT_ONLY_REGEX = /^#/
          LIB_REGEX = Regexp.union(LONG_FORM_NAME_VERSION_REGEX, NAME_VERSION_REGEX)

          def self.file_name_glob
            'pyproject.toml'
          end

          def self.lang_name
            'Python'
          end

          private

          ### Example format:
          #
          # [tool.poetry.dependencies]
          # zlib = "^1.2.1"
          # tomlkit = ">=0.11.4,<1.0.0" # Version range
          # # Long form version specifier
          # cachecontrol = { version = ">=0.14.0", extras = ["filecache"] }
          #
          # [tool.poetry.dev-dependencies] # May have different prefix, e.g. "test-dependencies"
          # pytest = "^7.0.0"
          # black = "^23.1.0"
          #
          # [tool.poetry.group.test.dependencies]
          # pytest-xdist = { version = ">=3.1", extras = ["psutil"] }
          #
          def extract_libs
            # We are not using TomlRB.parse() because it would require us to recursively find "dependencies"
            # nodes at unknown depths, which could be more costly than parsing line-by-line.
            in_deps_section = false

            libs = content.each_line.lazy.filter_map do |line|
              line.strip!
              next if line.blank? || COMMENT_ONLY_REGEX.match?(line)

              if START_ANY_SECTION_REGEX.match?(line)
                in_deps_section = START_DEPS_SECTION_REGEX.match?(line)
                next
              end

              parse_lib(line) if in_deps_section
            end

            libs.first(::Projects::XrayReport::MAX_LIBS)
          end

          def parse_lib(line)
            match = LIB_REGEX.match(line)

            Lib.new(name: match[:name], version: match[:version]) if match
          end
        end
      end
    end
  end
end

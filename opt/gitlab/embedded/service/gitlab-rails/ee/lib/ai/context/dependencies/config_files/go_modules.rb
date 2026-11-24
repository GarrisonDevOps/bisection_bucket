# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class GoModules < Base
          KEYWORD = 'require ' # Identifies the dependencies section/line
          EXCLUDE_KEYWORD = '// indirect' # Indirect dependencies are excluded
          START_SECTION_REGEX = /^#{KEYWORD}\(/
          END_SECTION_REGEX = /^\)/
          SINGLE_LINE_REGEX = /^#{KEYWORD}/
          REQUIRE_DIRECTIVE_REGEX = /^\s*require\b/

          def self.file_name_glob
            'go.mod'
          end

          def self.lang_name
            'Go'
          end

          private

          ### Example format:
          #
          # require golang.org/x/mod v0.15.0
          # require github.com/pmezard/go-difflib v1.0.0 // indirect
          #
          # require (
          #   github.com/kr/text v0.2.0 // indirect
          #   go.uber.org/goleak v1.3.0
          # )
          #
          def extract_libs
            libs = []
            in_deps_section = false

            each_line_until_capped(libs) do |line|
              line.strip!

              if START_SECTION_REGEX.match?(line)
                in_deps_section = true
              elsif END_SECTION_REGEX.match?(line)
                in_deps_section = false
              elsif in_deps_section || SINGLE_LINE_REGEX.match?(line)
                libs << parse_lib(line) unless line.include?(EXCLUDE_KEYWORD)
              end
            end

            libs
          end

          def parse_lib(line)
            line.delete_prefix!(KEYWORD)
            name, version = line.split(' ')

            Lib.new(name: name, version: version)
          end

          # Any require directive counts, even one `extract_libs` skips, such as an indirect dependency
          def lists_dependencies?
            REQUIRE_DIRECTIVE_REGEX.match?(content)
          end
        end
      end
    end
  end
end

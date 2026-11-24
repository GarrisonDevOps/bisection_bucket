# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class CppConanTxt < Base
          START_SECTION_REGEX = /^\[requires\]/ # Identifies the dependencies section
          START_NEXT_SECTION_REGEX = /^\[/
          COMMENT_ONLY_REGEX = /^#/

          def self.file_name_glob
            'conanfile.txt'
          end

          def self.lang_name
            'C++'
          end

          private

          ### Example format:
          #
          # [requires]
          # libiconv/1.17
          # openssl/3.2.2u # An inline comment
          # poco/[>1.0,<1.9]
          # # A comment-only line
          # zlib/1.2.13#revision1
          # boost/1.67.0@conan/stable
          #
          def extract_libs
            libs = []
            in_deps_section = false

            each_line_until_capped(libs) do |line|
              line.strip!
              next if line.blank? || COMMENT_ONLY_REGEX.match?(line)

              if in_deps_section
                break if START_NEXT_SECTION_REGEX.match?(line)

                libs << parse_lib(line)
              elsif START_SECTION_REGEX.match?(line)
                in_deps_section = true
              end
            end

            libs
          end

          def parse_lib(line)
            name_version, _ = line.split(/@|#/)
            name, version = name_version.split('/')
            version&.gsub!(/\[|\]/, '') # Version could be a range, e.g. [>1.0,<1.9]

            Lib.new(name: name, version: version)
          end
        end
      end
    end
  end
end

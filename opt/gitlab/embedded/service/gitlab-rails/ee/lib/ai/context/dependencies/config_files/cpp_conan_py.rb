# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class CppConanPy < CppConanTxt
          SINGLE_LINE_REGEX = /^self.requires\(/ # Identifies a single line requirement
          START_SECTION_REGEX = /^requires\s*=\s*/ # Identifies a single or multi-line tuple/list of requirements
          OPENING_BRACKETS_REGEX = %r{(?<!/)(\(|\[)} # Ignores the bracket in a version range (e.g. "poco/[>1.0 <1.9]")
          CLOSING_BRACKETS_REGEX = /(\)|\])$/
          LINE_CONTINUATION_REGEX = /\\/
          QUOTED_VALUE_REGEX = /"(?<value>[^"]+)"/
          COMMENT_ONLY_REGEX = /^#/
          INLINE_COMMENT_REGEX = /\s+#.*$/
          STRING_INTERPOLATION_CHARS = '{}'

          def self.file_name_glob
            'conanfile.py'
          end

          def self.lang_name
            'C++'
          end

          private

          ### Example format with `self.requires`:
          #
          # class SampleConan(ConanFile):
          #   other_lib = "my_other_lib"
          #   version = "1.2.3"
          #
          #   def requirements(self):
          #       self.requires("fmt/6.0.0@bin/stable")
          #       self.requires("poco/[>1.0 <1.9]") # Range of versions specified
          #       self.requires("glog/0.5.0#revision1")
          #       self.requires("protobuf", visible=True) # With additional param
          #
          #       # String interpolation is not supported; below outputs nil as version
          #       self.requires("my_lib/{}".format(version))
          #       # Where the library name must be interpolated, the entire line is ignored
          #       self.requires("{}/3.0.0".format(other_lib))
          #
          #       if (self.condition):
          #           self.requires("zlib")
          #
          ### Example format with `requires =`: The assigned value can be a single or multi-line Python tuple (round
          ### brackets optional) or list (square brackets required). The spacing around the `=` operator is optional.
          #
          # class SampleConan(ConanFile):
          #   requires = ("boost/1.76.0", "fmt/6.0.0@bin/stable")
          #
          ### Other variations using `requires =`:
          #
          #   requires = "boost/1.76.0", "fmt/6.0.0@bin/stable"
          #
          #   requires=(
          #       "boost/1.76.0",
          #       # A comment
          #       "fmt/6.0.0@bin/stable"
          #   )
          #
          #   requires = "boost/1.76.0", \ # A comment
          #              "opencv/4.6.0"
          #
          #   requires=["boost/1.76.0", "fmt/6.0.0@bin/stable"]
          #
          def extract_libs
            libs = []
            in_deps_section = false
            has_opening_brackets = false

            each_line_until_capped(libs) do |line|
              line.strip!
              next if line.blank? || COMMENT_ONLY_REGEX.match?(line)

              line.gsub!(INLINE_COMMENT_REGEX, '')

              unless in_deps_section
                if SINGLE_LINE_REGEX.match?(line)
                  lib = parse_line(line)
                  libs << lib if lib
                elsif START_SECTION_REGEX.match?(line)
                  in_deps_section = true
                  has_opening_brackets = true if OPENING_BRACKETS_REGEX.match?(line)
                end
              end

              next unless in_deps_section

              # One line can list any number of requirements, so read them lazily up to the cap:
              # `each_line(',')` yields one piece at a time, where `split` would build them all first
              remaining = ::Projects::XrayReport::MAX_LIBS - libs.size
              libs.concat(line.each_line(',').lazy.filter_map { |l| parse_line(l) }.first(remaining))

              next if LINE_CONTINUATION_REGEX.match?(line)
              next if has_opening_brackets && !CLOSING_BRACKETS_REGEX.match?(line)

              break
            end

            libs
          end

          def parse_line(line)
            match = QUOTED_VALUE_REGEX.match(line)
            return unless match

            lib = parse_lib(match[:value])

            lib.version = nil if lib.version&.include?(STRING_INTERPOLATION_CHARS)
            lib unless lib.name&.include?(STRING_INTERPOLATION_CHARS)
          end
        end
      end
    end
  end
end

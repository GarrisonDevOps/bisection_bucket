# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class JavaGradle < Base
          START_DEPS_SECTION_REGEX = /^dependencies\s*{\s*/ # Identifies the dependencies section
          END_SECTION_REGEX = /^}$/
          START_EXT_SECTION_REGEX = /^ext\s*{\s*/ # Identifies the ext section where variables are set
          PREFIX_REGEX = /^['"]?(implementation|testImplementation)['"]?/ # Appears before each dependency
          LONG_FORM_NAME_REGEX = /name:\s*(?<value>[^,\s]*)/
          LONG_FORM_VERSION_REGEX = /version:\s*(?<value>[^,\s]*)/
          # Matches value of digits and periods between double or single quotes
          VALID_VERSION_REGEX = /(?<quote>["'])(?<value>[\d+(.)]*)\k<quote>/
          QUOTED_VALUE_REGEX = /(?<quote>["'])(?<value>[^"']+)\k<quote>/ # Matches value between double or single quotes
          INLINE_COMMENT_REGEX = %r{\s+//.*$}
          STRING_INTERPOLATION_CHAR = '$'
          EXCLUDE_KEYWORD = '('

          def self.file_name_glob
            'build.gradle'
          end

          def self.lang_name
            'Java'
          end

          private

          ### Example format:
          #
          # ext {
          #     arcgisVersion = '4.5.0'
          # }
          #
          # dependencies {
          #     // Short form: <group>:<name>:<version>
          #     implementation 'org.codehaus.groovy:groovy:3.+'
          #     testImplementation "com.google.guava:guava:29.0.1" // Inline comment
          #     // The quotes on `implementation` may be a legacy format; ported from Repository X-Ray Go repo
          #     "implementation" 'org.ow2.asm:asm:9.6'
          #
          #     // Long form
          #     implementation group: "org.neo4j", name: "neo4j-jmx", version: "1.3"
          #     testImplementation group: 'junit', name: 'junit', version: '4.11'
          #     "testImplementation" group: "org.apache.ant", name: "ant", version: "1.10.14"
          #
          #     // Project, file, or other dependencies are ignored
          #     implementation project(':utils')
          #     runtimeOnly files('libs/a.jar', 'libs/b.jar')
          #
          #     // String interpolation is supported. The versions are read from the 'ext' section
          #     implementation "com.esri.arcgisruntime:arcgis-java:$arcgisVersion"
          # }
          #
          def extract_libs
            versions_to_be_interpolated = {}
            names_to_be_interpolated = {}
            libs = []
            in_deps_section = false
            in_ext_section = false

            each_line_until_capped(libs) do |line|
              line.strip!
              line.gsub!(INLINE_COMMENT_REGEX, '')

              if in_ext_section
                if line.rstrip == "}"
                  in_ext_section = false
                  next
                end

                val_split = line.delete(' ').split('=')
                val_name = val_split[0]
                val_value = val_split[1]

                if VALID_VERSION_REGEX.match?(val_value)
                  versions_to_be_interpolated["$#{val_name}"] = val_value.delete!('"\'')
                elsif QUOTED_VALUE_REGEX.match?(val_value)
                  names_to_be_interpolated["$#{val_name}"] = val_value.delete!('"\'')
                end
              elsif START_EXT_SECTION_REGEX.match?(line)
                in_ext_section = true
              end

              if in_deps_section
                if PREFIX_REGEX.match?(line)
                  lib = parse_lib(line, names_to_be_interpolated, versions_to_be_interpolated)
                  libs << lib if lib
                end

                break if line.rstrip == "}"
              elsif START_DEPS_SECTION_REGEX.match?(line)
                in_deps_section = true
              end
            end

            libs
          end

          def parse_lib(line, names_to_be_interpolated, versions_to_be_interpolated)
            line.gsub!(PREFIX_REGEX, '')
            return if line.include?(EXCLUDE_KEYWORD)

            long_form_name_match = LONG_FORM_NAME_REGEX.match(line)

            if long_form_name_match
              # Parse long form
              name = long_form_name_match[:value].delete('"\'')
              version_match = LONG_FORM_VERSION_REGEX.match(line)
              version = version_match[:value].delete('"\'') if version_match
            else
              # Parse short form
              depedency_match = QUOTED_VALUE_REGEX.match(line)
              _group, name, version = depedency_match[:value].split(':') if depedency_match
            end

            if name&.include?(STRING_INTERPOLATION_CHAR)
              return unless names_to_be_interpolated.key?(name)

              name = names_to_be_interpolated[name]
            end

            if version&.include?(STRING_INTERPOLATION_CHAR)
              version = versions_to_be_interpolated.key?(version) ? versions_to_be_interpolated[version] : nil
            end

            Lib.new(name: name, version: version)
          end
        end
      end
    end
  end
end

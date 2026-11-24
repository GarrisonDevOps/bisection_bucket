# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        class KotlinGradle < Base
          PREFIX_REGEX = /^(implementation|testImplementation)\(/ # Appears before each dependency
          START_DEPS_SECTION_REGEX = /^dependencies\s*{\s*/ # Identifies the dependencies section
          # Matches value of digits and periods between double or single quotes
          VALID_VERSION_REGEX = /(?<quote>["'])(?<value>[\d+(.)]*)\k<quote>/
          QUOTED_VALUE_REGEX = /(?<quote>["'])(?<value>[^"']+)\k<quote>/ # Matches value between double or single quotes
          INLINE_COMMENT_REGEX = %r{\s+//.*$}
          STRING_INTERPOLATION_CHAR = '$'
          EXCLUDE_KEYWORD = '('
          VAL_KEYWORD = 'val'

          def self.file_name_glob
            'build.gradle.kts'
          end

          def self.lang_name
            'Kotlin'
          end

          private

          ### Example format:
          #
          # // Supported plain string interpolation
          # val arcgisVersion = "1.0.0"
          #
          # // Not supported string interpolation
          # val kotlinVersion = file("../kotlin-dsl/$kotlinVersionSourceFilePath").readLines().extractKotlinVersion()
          #
          # dependencies {
          #     // Format <group>:<name>:<version>
          #     implementation("org.codehaus.groovy:groovy:3.+")
          #     testImplementation("com.google.guava:guava:29.0.1") // Inline comment
          #
          #     // Project, file, or other dependencies are ignored
          #     implementation(project(":utils"))
          #     runtimeOnly(files("libs/a.jar", "libs/b.jar"))
          #
          #     // String interpolation is supported
          #     implementation("com.esri.arcgisruntime:arcgis-java:$arcgisVersion")
          # }
          #
          def extract_libs
            versions_to_be_interpolated = {}
            names_to_be_interpolated = {}
            libs = []
            in_deps_section = false

            each_line_until_capped(libs) do |line|
              line.strip!
              line.gsub!(INLINE_COMMENT_REGEX, '')

              if line.start_with?("#{VAL_KEYWORD} ")
                split_val = line.split(VAL_KEYWORD, 2)[1].delete(' ').split('=')

                if split_val.length < 3
                  val_name = split_val[0]
                  val_value = split_val[1]

                  if VALID_VERSION_REGEX.match?(val_value)
                    versions_to_be_interpolated["$#{val_name}"] =
                      val_value.delete!('"\'')
                  end

                  if QUOTED_VALUE_REGEX.match?(val_value)
                    names_to_be_interpolated["$#{val_name}"] =
                      val_value.delete!('"\'')
                  end
                end
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

            depedency_match = QUOTED_VALUE_REGEX.match(line)
            return unless depedency_match

            _group, name, version = depedency_match[:value].split(':') if depedency_match

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

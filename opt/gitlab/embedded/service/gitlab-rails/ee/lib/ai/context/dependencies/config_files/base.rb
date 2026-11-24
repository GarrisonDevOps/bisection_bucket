# frozen_string_literal: true

module Ai
  module Context
    module Dependencies
      module ConfigFiles
        # This class represents a dependency manager config file. It contains
        # logic to parse, extract, and process libraries from the file content.
        #
        # To support a new config file type/language:
        # 1. Create a new child class that inherits from this Base. The file name should be in
        #    the format: `<lang>_<dependency_manager_name>(_<additional_file_identifier>)`
        #    The additional file identifier should be "lock" when applicable.
        # 2. Add the new class to `ConfigFiles::Constants::CONFIG_FILE_CLASSES` and update
        #    the corresponding documentation (see comments in ConfigFiles::Constants.)
        #
        class Base
          EXPECTED_VERSION_TYPES = [String, Integer, Float, NilClass].freeze

          VALID_NAME_REGEX = %r{\A[a-zA-Z0-9][\w/\-.]*[a-zA-Z0-9]\z} # Must start and end with alphanumeric
          VALID_VERSION_REGEX = /\A[0-9 .<>=+^*!|,]+\z/
          MAX_NAME_LENGTH = 60
          MAX_VERSION_LENGTH = 30
          MAX_MATCHING_FILES = 10

          VERSION_PREFIX_REGEX = /\bv(?=\d)/
          VERSION_QUALIFIER_REGEX = /(?<=\d)([-|+][0-9A-Za-z.\-+]+)/ # Pre-release and/or build metadata
          VERSION_ALPHABETIC_POSTFIX_REGEX = /(?<=\d)([a-zA-Z]+)/

          StringValidationError = Class.new(StandardError)

          Lib = Struct.new(:name, :version, keyword_init: true)

          def self.file_name_glob
            raise NotImplementedError
          end

          def self.lang_name
            raise NotImplementedError
          end

          def self.lang
            ::CodeSuggestions::ProgrammingLanguage::LANGUAGE_XRAY_NAMING[lang_name]
          end

          def self.matches?(path)
            File.fnmatch?("**/#{file_name_glob}", path, File::FNM_PATHNAME | File::FNM_DOTMATCH)
          end

          # Set to `true` if the dependency manager supports more than one config file
          def self.supports_multiple_files?
            false
          end

          def self.matching_paths(paths)
            return Array.wrap(paths.find { |p| matches?(p) }) unless supports_multiple_files?

            # Every matching file is loaded at once, so keep only the ones nearest the repository root
            paths.select { |p| matches?(p) }.sort_by { |p| [p.count('/'), p] }.first(MAX_MATCHING_FILES)
          end

          def initialize(blob, project)
            @blob = blob
            @project = project
            @content = sanitize_content(blob.data)
            @path = blob.path
          end

          def parse!
            raise ParsingErrors::FileEmptyError if content.blank?

            # Capped before validation: a report keeps at most MAX_LIBS, so validating more only burns CPU.
            @libs = process_libs(Array.wrap(extract_libs).first(::Projects::XrayReport::MAX_LIBS))

            raise ParsingErrors::DependenciesNotPresentError if libs.blank? && !lists_dependencies?
            raise ParsingErrors::UnexpectedFormatOrDependenciesNotPresentError if libs.blank?
          rescue ParsingErrors::BaseError, StringValidationError => e
            @error = e
            log_error
          end

          def payload
            return unless valid?

            {
              libs: formatted_libs,
              file_path: path
            }
          end

          def valid?
            error.nil?
          end

          def error_message
            return if valid?

            "Error while parsing file `#{path}`: #{error.message}"
          end

          # Blank, or listing nothing, as opposed to listing dependencies that could not be read
          def no_dependencies?
            error.is_a?(ParsingErrors::FileEmptyError) || error.is_a?(ParsingErrors::DependenciesNotPresentError)
          end

          private

          attr_reader :blob, :content, :path, :libs, :error, :project

          def extract_libs
            raise NotImplementedError
          end

          # A file that yields no library may still list dependencies the parser can't read, such as packages
          # from a private registry, so only parsers that can tell the file lists nothing override this.
          def lists_dependencies?
            true
          end

          # For line-based parsers: stops reading once `libs` holds as many libraries as a report keeps
          def each_line_until_capped(libs)
            content.each_line do |line|
              break if libs.size >= ::Projects::XrayReport::MAX_LIBS

              yield line
            end
          end

          def process_libs(libs)
            Array.wrap(libs).each do |lib|
              raise ParsingErrors::UnexpectedDependencyNameTypeError, lib.name.class unless lib.name.is_a?(String)
              raise ParsingErrors::BlankDependencyNameError if lib.name.blank?

              unless lib.version.class.in?(EXPECTED_VERSION_TYPES)
                raise ParsingErrors::UnexpectedDependencyVersionTypeError, lib.version.class
              end

              lib.name = lib.name.strip
              lib.version = sanitize_version(lib.version)

              validate_name!(lib.name)
              validate_version!(lib.version) if lib.version.present?
            end
          end

          def validate_name!(name)
            unless name.size <= MAX_NAME_LENGTH
              raise StringValidationError, "dependency name `#{name.truncate(MAX_NAME_LENGTH * 2)}` " \
                "exceeds #{MAX_NAME_LENGTH} characters"
            end

            return if VALID_NAME_REGEX.match?(name)

            raise StringValidationError, "dependency name `#{name}` contains invalid characters"
          end

          def validate_version!(version)
            unless version.size <= MAX_VERSION_LENGTH
              raise StringValidationError, "dependency version `#{version.truncate(MAX_VERSION_LENGTH * 2)}` " \
                "exceeds #{MAX_VERSION_LENGTH} characters"
            end

            return if VALID_VERSION_REGEX.match?(version)

            raise StringValidationError, "dependency version `#{version}` contains invalid characters"
          end

          # Removes any version qualifiers that may fail validation
          def sanitize_version(version)
            regex_union = Regexp.union(VERSION_PREFIX_REGEX, VERSION_QUALIFIER_REGEX, VERSION_ALPHABETIC_POSTFIX_REGEX)
            version.to_s.strip.gsub(regex_union, '')
          end

          def sanitize_content(content)
            content
              .encode('UTF-8', invalid: :replace, undef: :replace, replace: '')
              .delete("\u0000") # NULL byte is not permitted in JSON nor in PostgreSQL text-based columns
          end

          def formatted_libs
            libs.map do |lib|
              name = lib.version.presence ? "#{lib.name} (#{lib.version})" : lib.name

              { name: name }
            end
          end

          # dig() throws a generic error in certain cases, e.g. when accessing an array with
          # a string key or calling it on an integer or nil. This method wraps dig() so that
          # we can capture these exceptions and re-raise them with a specific error message.
          def dig_in(obj, *keys)
            obj.dig(*keys)
          rescue NoMethodError, TypeError
            raise ParsingErrors::UnexpectedNodeError
          end

          def log_error
            ::Gitlab::AppJsonLogger.info(
              class: self.class.name,
              error_class: error.class.name,
              message: "#{self.class.name}: #{error.message}",
              project_id: project.id
            )
          end
        end
      end
    end
  end
end

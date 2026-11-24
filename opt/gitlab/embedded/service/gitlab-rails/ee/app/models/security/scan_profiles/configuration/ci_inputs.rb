# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration
      module CiInputs
        MAX_LENGTH = 16_384

        # String inputs land in double-quoted shell text and rule literals, so anything that can break out is rejected.
        UNSAFE_CHARS = /
          [\x00-\x1f\x7f] # control characters, including newline and NUL
          | ["'`]         # quotes close the string or `${X:-...}`; a backtick starts a command substitution
          | [$}]          # `$` starts an expansion and is re-read by later inputs; `}` closes `${X:-...}` early
          | \\            # backslash escape
        /x

        GUARDS = {
          # Booleans and numbers are validated on save by the JSON schema and again when the pipeline is built, by
          # `Gitlab::Ci::Config::Interpolation::Inputs`, so they pass through here.
          boolean: :itself.to_proc,
          number: :itself.to_proc,
          string: ->(value) { safe_string(value) },
          comma_separated_strings: ->(value) { safe_string(Array(value).join(',')) }
        }.freeze

        MAPPINGS = {
          dependency_scanning: {
            excluded_paths: { input: :excluded_paths, type: :comma_separated_strings },
            max_depth: { input: :max_scan_depth, type: :number },
            include_dev_dependencies: { input: :include_dev_dependencies, type: :boolean },
            static_reachability_enabled: { input: :enable_static_reachability, type: :boolean },
            enable_manifest_fallback: { input: :enable_manifest_fallback, type: :boolean },
            disabled_resolution_jobs: { input: :disabled_resolution_jobs, type: :comma_separated_strings },
            maven_resolution_image: { input: :maven_resolution_image, type: :string },
            gradle_resolution_image: { input: :gradle_resolution_image, type: :string },
            python_resolution_image: { input: :python_resolution_image, type: :string },
            api_timeout: { input: :vulnerability_scan_api_timeout, type: :number },
            secure_log_level: { input: :analyzer_log_level, type: :string },
            enable_vulnerability_scan: { input: :enable_vulnerability_scan, type: :boolean },
            api_scan_download_delay: { input: :vulnerability_scan_api_download_delay, type: :number },
            maven_dependency_plugin_version: { input: :maven_dependency_plugin_version, type: :string },
            pip_manifest_file_name_pattern: { input: :pip_manifest_file_name_pattern, type: :string },
            pipcompile_lockfile_file_name_pattern: { input: :pipcompile_lockfile_file_name_pattern, type: :string },
            analyzer_image_version: { input: :analyzer_image_version, type: :string }
          }
        }.freeze

        def self.build(scan_type, config)
          symbolized = config.to_h.deep_symbolize_keys

          MAPPINGS.fetch(scan_type&.to_sym, {}).each_with_object({}) do |(key, definition), inputs|
            next if symbolized[key].nil?

            value = GUARDS.fetch(definition[:type]).call(symbolized[key])
            inputs[definition[:input]] = value unless value.nil?
          end
        end

        def self.safe_string(value)
          value if value.is_a?(String) &&
            value.encoding == Encoding::UTF_8 &&
            value.valid_encoding? &&
            !value.empty? &&
            value.length <= MAX_LENGTH &&
            !UNSAFE_CHARS.match?(value)
        end
        private_class_method :safe_string
      end
    end
  end
end

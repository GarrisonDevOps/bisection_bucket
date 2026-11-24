# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    # Parses the output.json artifact produced by the dependency management
    # orchestrator. Extracts only the fields needed to commit files and
    # create a merge request.
    #
    # See: https://gitlab.com/gitlab-org/security-products/dependency-management/orchestrator
    class OutputParser
      ParseError = Class.new(StandardError)

      DependencyChange = Struct.new(:name, :previous_version, :version, keyword_init: true)
      UpdatedFile = Struct.new(:path, :content, :encoding, keyword_init: true)
      # A dependency the job asked for that the updater reports as not updated, with the stage and the reason.
      FailedDependency = Struct.new(:name, :directory, :stage, :reason, keyword_init: true)
      Result = Struct.new(:dependencies, :updated_files, :failed_dependencies, keyword_init: true) do
        def version_for(name)
          wanted = OutputParser.comparable_name(name)
          dependencies.find { |dependency| OutputParser.comparable_name(dependency.name) == wanted }&.version
        end
      end

      # Updater and SBOM spellings of a package name can differ in case, so every name comparison goes through here.
      def self.comparable_name(name)
        name.to_s.downcase(:fold)
      end

      # @param raw_json [String] raw content of output.json
      # @param failed_overrides_updated [Boolean] whether a name in both arrays counts as failed, as a batch needs.
      #   Single-dependency runs keep it.
      # @return [Result]
      def self.parse(raw_json, failed_overrides_updated: false)
        data = Gitlab::Json.safe_parse(raw_json)
        raise ParseError, 'output.json must be a JSON object' unless data.is_a?(Hash)

        failed = parse_failed_dependencies(data)
        failed_names = failed_overrides_updated ? failed.to_set { |dep| comparable_name(dep.name) } : Set.new

        Result.new(
          # The updater lists a dependency in both arrays when its file update failed after its check.
          dependencies: parse_dependencies(data).reject { |dep| failed_names.include?(comparable_name(dep.name)) },
          updated_files: parse_updated_files(data),
          failed_dependencies: failed
        )
      rescue JSON::ParserError => e
        raise ParseError, "Invalid JSON in output.json: #{e.message}"
      end

      def self.parse_dependencies(data)
        Array(data['dependency_updates']).filter_map do |dep|
          next unless dep.is_a?(Hash) && dep['name'].present?

          DependencyChange.new(
            name: dep['name'].to_s,
            previous_version: dep['previous_version'].to_s,
            version: dep['new_version'].to_s
          )
        end
      end

      def self.parse_updated_files(data)
        Array(data['updated_files']).filter_map do |file|
          next unless file.is_a?(Hash) && file['directory'].present? && file['name'].present?

          path = sanitize_path(file['directory'], file['name'])
          next unless path

          UpdatedFile.new(
            path: path,
            content: file['content'].to_s,
            encoding: 'text'
          )
        end
      end

      def self.parse_failed_dependencies(data)
        Array(data['failed_dependencies']).filter_map do |entry|
          next unless entry.is_a?(Hash) && entry['name'].present?

          FailedDependency.new(
            name: entry['name'].to_s,
            directory: entry['directory'].to_s,
            stage: entry['stage'].to_s,
            reason: entry['reason'].to_s
          )
        end
      end

      def self.sanitize_path(directory, name)
        # Reject name values that are absolute paths (e.g. "/etc/passwd")
        # to prevent Pathname#join from discarding the directory entirely.
        return if name.start_with?('/')

        # The directory from the dependency updater always starts with a leading "/"
        # (e.g. "/" or "/src"), indicating the project root.
        # Strip the leading "/" so Pathname doesn't interpret it as an absolute filesystem path.
        relative_dir = directory.delete_prefix('/')
        normalized = Pathname.new(relative_dir).join(name).cleanpath.to_s

        return if normalized.start_with?('/', '..')

        normalized
      end

      private_class_method :parse_dependencies, :parse_updated_files, :parse_failed_dependencies, :sanitize_path
    end
  end
end

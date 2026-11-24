# frozen_string_literal: true

require "net/http"

module Gitlab
  module SecurityReportSchemas
    module CLI
      class IntegrityChecker
        # Represents the schema file located on GitLab.com
        class RemoteFile < AbstractFile
          SCHEMA_FILE_NAME_REGEX = %r{./+(?<version>\d+\.\d+\.\d+)/(?<file_name>.+-report-format\.json)$}

          private

          def content
            Net::HTTP.get(uri)
          end

          def uri
            URI(schema_url)
          end

          def schema_url
            format(schema_project_raw_url, version:, schema_file_name:)
          end

          def version
            schema_file_components["version"]
          end

          def schema_file_name
            schema_file_components["file_name"]
          end

          def schema_file_components
            @schema_file_components ||= schema_file.to_s.match(SCHEMA_FILE_NAME_REGEX).named_captures
          end

          def schema_project_raw_url
            "#{schema_project_url}/-/raw/v%<version>s/dist/%<schema_file_name>s"
          end

          def schema_project_url
            Gitlab::SecurityReportSchemas.configuration.schema_project_url
          end
        end
      end
    end
  end
end

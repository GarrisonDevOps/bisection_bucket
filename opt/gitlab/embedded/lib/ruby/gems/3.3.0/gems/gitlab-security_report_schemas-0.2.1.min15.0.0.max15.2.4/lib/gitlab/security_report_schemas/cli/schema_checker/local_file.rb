# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    module CLI
      class IntegrityChecker
        # Represents the local schema file
        class LocalFile < AbstractFile
          private

          def content
            File.read(schema_file)
          end
        end
      end
    end
  end
end

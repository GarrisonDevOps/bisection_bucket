# frozen_string_literal: true

require_relative "schema_checker/abstract_file"
require_relative "schema_checker/local_file"
require_relative "schema_checker/remote_file"

module Gitlab
  module SecurityReportSchemas
    module CLI
      # Checks the integrity of the schemas
      class IntegrityChecker
        def self.check!(version)
          new(version).check!
        end

        def initialize(version)
          @version = version
        end

        def check!
          local_schema_files.each do |schema_file|
            check_integrity_of!(schema_file)
          end
        end

        private

        attr_reader :version

        def local_schema_files
          schema_dir.children
        end

        def schema_dir
          SecurityReportSchemas.schemas_path.join(version)
        end

        def check_integrity_of!(schema_file)
          return if LocalFile.new(schema_file) == RemoteFile.new(schema_file)

          raise "Integrity of `#{schema_file}' is broken!"
        end
      end
    end
  end
end

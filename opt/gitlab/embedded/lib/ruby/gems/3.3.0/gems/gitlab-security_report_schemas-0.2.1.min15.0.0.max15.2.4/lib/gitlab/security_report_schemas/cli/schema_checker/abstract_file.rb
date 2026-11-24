# frozen_string_literal: true

module Gitlab
  module SecurityReportSchemas
    module CLI
      class IntegrityChecker
        # Encapsulates common schema file logic
        class AbstractFile
          def initialize(schema_file)
            @schema_file = schema_file
          end

          def ==(other)
            checksum == other.checksum
          end

          protected

          def checksum
            Digest::MD5.hexdigest(content)
          end

          private

          attr_reader :schema_file

          def content
            raise "Must be implemented by the subclass"
          end
        end
      end
    end
  end
end

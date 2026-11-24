# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Export
      class PurgeService
        def self.purge(archive_export)
          new(archive_export).purge
        end

        def initialize(archive_export)
          @archive_export = archive_export
        end

        def purge
          archive_export.remove_file!
          archive_export.purge!
        end

        private

        attr_reader :archive_export
      end
    end
  end
end

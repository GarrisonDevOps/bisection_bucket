# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      class RestoreForGroupService
        def self.execute(...)
          new(...).execute
        end

        def initialize(group)
          @group = group
        end

        def execute
          Vulnerabilities::Backups::Vulnerability.partition_models.each do |partition_model|
            RestoreFromPartitionService.execute(group, partition_model)
          end
        end

        private

        attr_reader :group
      end
    end
  end
end

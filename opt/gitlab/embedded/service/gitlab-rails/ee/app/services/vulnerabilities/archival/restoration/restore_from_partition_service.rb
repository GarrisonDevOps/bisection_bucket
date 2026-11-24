# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      class RestoreFromPartitionService
        BATCH_SIZE = 50

        def self.execute(...)
          new(...).execute
        end

        def initialize(group, partition)
          @group = group
          @partition = partition
        end

        def execute
          iterator.each_batch(of: BATCH_SIZE) do |batch|
            backups = cast_batch(batch)

            RestoreBatchService.execute(backups)
          end
        end

        private

        attr_reader :group, :partition

        delegate :traversal_ids, to: :group, private: true

        def iterator
          @iterator ||= Gitlab::Pagination::Keyset::Iterator.new(scope: backup_vulnerabilities)
        end

        def backup_vulnerabilities
          partition.within(traversal_ids).ordered_by_existence
        end

        def cast_batch(batch)
          batch.map { |record| record.becomes(Vulnerabilities::Backups::Vulnerability) } # rubocop:disable Cop/AvoidBecomes -- This doesn't cause any performance issues here.
        end
      end
    end
  end
end

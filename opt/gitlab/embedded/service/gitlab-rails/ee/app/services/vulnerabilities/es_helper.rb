# frozen_string_literal: true

module Vulnerabilities
  module EsHelper
    BATCH_SIZE = 1_000

    def self.sync_elasticsearch(vulnerability_ids)
      ids = Array(vulnerability_ids).compact.uniq
      return if ids.empty?

      ids.each_slice(BATCH_SIZE) do |batch_ids|
        relation = Vulnerability.id_in(batch_ids)
        ::Vulnerabilities::BulkEsOperationService.new(relation).execute
      end
    end
  end
end

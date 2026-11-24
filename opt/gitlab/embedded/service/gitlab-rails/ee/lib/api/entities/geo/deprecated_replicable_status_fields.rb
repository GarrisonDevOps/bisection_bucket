# frozen_string_literal: true

module API
  module Entities
    module Geo
      # Status fields of removed replicables. Removing a field
      # from REST API v4 is a breaking change, so they stay and return nil,
      # like the fields of a disabled replicable on a primary site.
      module DeprecatedReplicableStatusFields
        extend ActiveSupport::Concern

        REMOVED_REPLICABLES = %w[ai_vectorizable_file_uploads].freeze

        COUNT_SUFFIXES = %w[
          count
          checksum_total_count
          checksummed_count
          checksum_failed_count
          synced_count
          failed_count
          registry_count
          verification_total_count
          verified_count
          verification_failed_count
        ].freeze

        included do
          REMOVED_REPLICABLES.each do |replicable|
            COUNT_SUFFIXES.each do |suffix|
              expose :"#{replicable}_#{suffix}", documentation: { type: 'Integer', x: { nullable: true } } do |_status|
                nil
              end
            end

            expose :"#{replicable}_oldest_unsynced_time",
              documentation: { type: 'Integer', x: { nullable: true } } do |_status|
              nil
            end

            expose :"#{replicable}_synced_in_percentage",
              documentation: { type: 'String', example: '0.00%' } do |_status|
              '0.00%'
            end

            expose :"#{replicable}_verified_in_percentage",
              documentation: { type: 'String', example: '0.00%' } do |_status|
              '0.00%'
            end
          end
        end
      end
    end
  end
end

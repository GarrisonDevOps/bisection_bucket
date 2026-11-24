# frozen_string_literal: true

module Geo
  # Processes verification failures reported by a secondary (see
  # `POST /geo/failures`). Dispatches each entry by its `error_type` to the
  # service that knows how to self-heal it. The endpoint and this worker are
  # deliberately generic so a future error type can be added by adding a new
  # `when` branch here, without changing the API contract.
  class VerificationFailureReportWorker
    include ApplicationWorker
    include Gitlab::Geo::LogHelpers

    prepend ::Geo::SkipSecondary

    MAX_FAILURES_PER_REQUEST = 100
    CHECKSUM_MISMATCH = 'checksum_mismatch'

    idempotent!
    deduplicate :until_executing
    data_consistency :sticky
    feature_category :geo_replication

    def perform(geo_node_id, failures)
      by_error_type = Array(failures).map(&:deep_symbolize_keys).group_by { |failure| failure[:error_type] }

      by_error_type.each do |error_type, entries|
        dispatch(error_type, geo_node_id, entries)
      end
    end

    private

    def dispatch(error_type, geo_node_id, entries)
      case error_type
      when CHECKSUM_MISMATCH
        Geo::ChecksumMismatchSelfHealService.new(geo_node_id: geo_node_id, failures: entries).execute
      else
        log_info('Unknown verification failure error_type, skipping', error_type: error_type, count: entries.size)
      end
    end
  end
end

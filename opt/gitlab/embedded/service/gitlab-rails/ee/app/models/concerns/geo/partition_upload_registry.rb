# frozen_string_literal: true

module Geo
  # Overrides registry_consistency_worker_enabled? so that the Geo
  # consistency worker does not create duplicate registry rows when the
  # legacy Upload replicator (geo_upload_replication) is also active.
  #
  # When both geo_upload_replication and a partition-specific flag are
  # enabled simultaneously, the consistency worker would otherwise fill in
  # rows in both Geo::UploadRegistry and the partition registry table for
  # the same upload record. Disabling the worker for the partition registry
  # in that case lets the legacy replicator take precedence.
  #
  # Include this in every partition upload registry class
  # (e.g. Geo::AbuseReportUploadRegistry, Geo::GroupUploadRegistry,
  # Geo::ProjectUploadRegistry).
  module PartitionUploadRegistry
    extend ActiveSupport::Concern

    class_methods do
      def registry_consistency_worker_enabled?
        super && !::Geo::UploadReplicator.replication_enabled?
      end
    end
  end
end

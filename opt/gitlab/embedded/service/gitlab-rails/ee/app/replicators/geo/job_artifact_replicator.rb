# frozen_string_literal: true

module Geo
  class JobArtifactReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy

    def self.model
      ::Ci::JobArtifact
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|CI Job Artifact')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|CI Job Artifacts')
    end

    override :checksummed_count
    def self.checksummed_count
      return unless verification_enabled?

      if summaries_available?
        CiJobArtifactVerificationSummary.sum(:verified_count)
      else
        batch_count(model.verification_state_table_class.with_verification_state(:verification_succeeded))
      end
    end

    override :checksum_failed_count
    def self.checksum_failed_count
      return unless verification_enabled?

      if summaries_available?
        CiJobArtifactVerificationSummary.sum(:failed_count)
      else
        batch_count(model.verification_state_table_class.with_verification_state(:verification_failed))
      end
    end

    override :checksum_total_count
    def self.checksum_total_count
      return unless verification_enabled?

      if summaries_available?
        CiJobArtifactVerificationSummary.sum(:total_count)
      else
        batch_count(model.verification_state_table_class.all)
      end
    end

    def self.summaries_available?
      Feature.enabled?(:geo_job_artifact_verification_summaries, :instance)
    end
    private_class_method :summaries_available?

    def carrierwave_uploader
      model_record.file
    end

    # p_ci_job_artifacts is partitioned by partition_id. Including it in the
    # payload lets Gitlab::Geo::LogCursor::Events::Event#skip_enqueue? prune
    # to a single partition instead of planning an Append across all of them.
    override :event_params
    def event_params
      super.merge("partition_id" => model_record.partition_id)
    end
  end
end

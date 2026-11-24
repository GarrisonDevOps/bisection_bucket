# frozen_string_literal: true

module Geo
  # Legacy replicator for the whole uploads table. Disabled by default since
  # GitLab 19.6 in favour of the upload partition replicators. Removal is
  # tracked in https://gitlab.com/groups/gitlab-org/-/work_items/23545.
  class UploadReplicator < Gitlab::Geo::Replicator
    include ::Geo::BlobReplicatorStrategy
    include ::Geo::Concerns::UploadReplicatorBehavior

    def self.model
      ::Upload
    end

    # @return [String] human-readable title of this replicator.
    def self.replicable_title
      s_('Geo|Upload')
    end

    # @return [String] human-readable title of this replicator, pluralized.
    def self.replicable_title_plural
      s_('Geo|Uploads')
    end

    # uploads is partitioned by LIST (model_type). Including it in the payload
    # lets Gitlab::Geo::LogCursor::Events::Event#skip_enqueue? prune to a single
    # partition instead of planning an Append across all of them.
    #
    # Only relevant here, on the legacy generic replicator: once a model_type's
    # events are consumed by its own upload partition replicator (e.g.
    # Geo::AppearanceUploadReplicator), the query already targets that
    # partition's own table directly.
    override :event_params
    def event_params
      super.merge("model_type" => model_record.model_type)
    end

    # An Upload's upload_state is its own state, not a parent's. On a secondary,
    # copying it would compare the primary's checksum with itself.
    override :parent_upload_verification_succeeded?
    def parent_upload_verification_succeeded?
      false
    end
  end
end

# frozen_string_literal: true

module EE
  module MergeRequestDiff
    extend ActiveSupport::Concern

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :merge_request_diff_detail)

      with_replicator ::Geo::MergeRequestDiffReplicator

      has_one :merge_request_diff_detail, autosave: false, inverse_of: :merge_request_diff

      scope :has_external_diffs, -> { with_files.where(stored_externally: true) }
      scope :project_id_in, ->(ids) { where(merge_request_id: ::MergeRequest.where(target_project_id: ids)) }
      scope :available_replicables, -> { has_external_diffs }

      # Mirrors the after_create_commit/after_destroy hooks in Geo::ReplicableModel, which
      # also publish Geo events from the model rather than from callers, so
      # DeleteDiffFilesWorker and MergeRequests::DeleteNonLatestDiffsService don't need to
      # know about Geo replication.
      after_save_commit :geo_handle_diff_cleaned

      def verification_state_object
        merge_request_diff_detail
      end

      # When a diff transitions to `without_files` (for example via
      # `DeleteDiffFilesWorker#clean!`), it leaves `available_replicables`
      # (`has_external_diffs`) without being destroyed, so no Geo delete event
      # is emitted. Publish one here so secondaries remove the now out-of-scope
      # registry and its replicated blob right away instead of waiting for the
      # registry consistency worker to reach that record.
      def geo_handle_diff_cleaned
        return unless saved_change_to_state? && without_files? && stored_externally?

        replicator.geo_handle_after_destroy
      rescue StandardError => err
        log_error("Geo diff-cleaned event failed", err)
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of merge_request_diffs based on the query given in `query`.
      #
      # @param [String] query term that will search over external_diff attribute
      #
      # @return [ActiveRecord::Relation<MergeRequestDiff>] a collection of merge request diffs
      def search(query)
        return all if query.empty?

        where(sanitize_sql_for_conditions({ external_diff: query })).limit(1000)
      end

      # @return [ActiveRecord::Relation<MergeRequestDiff>] scope observing selective
      #         sync settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

        return replicables unless node.selective_sync?

        replicables.project_id_in(::Project.selective_sync_scope(node))
      end

      override :verification_state_table_class
      def verification_state_table_class
        MergeRequestDiffDetail
      end
    end

    def merge_request_diff_detail
      super || build_merge_request_diff_detail
    end
  end
end

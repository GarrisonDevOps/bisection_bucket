# frozen_string_literal: true

module Geo
  module ReplicableCiArtifactable
    extend ActiveSupport::Concern

    class_methods do
      extend ::Gitlab::Utils::Override

      # @return [ActiveRecord::Relation<Ci::{PipelineArtifact|JobArtifact|SecureFile}>] scope
      #         observing selective sync settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

        return replicables unless node.selective_sync?

        replicables_project_ids = replicables.loose_index_scan(column: :project_id).pluck(:project_id) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the number of distinct project_id values

        selective_projects_ids  =
          ::Project.selective_sync_scope(node)
            .id_in(replicables_project_ids)
            .pluck_primary_key

        replicables.project_id_in(selective_projects_ids)
      end
    end
  end
end

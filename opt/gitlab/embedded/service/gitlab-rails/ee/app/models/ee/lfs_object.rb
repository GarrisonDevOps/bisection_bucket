# frozen_string_literal: true

module EE
  # LFS Object EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `LfsObject` model
  module LfsObject
    extend ActiveSupport::Concern

    STORE_COLUMN = :file_store

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :lfs_object_state)

      with_replicator ::Geo::LfsObjectReplicator

      has_one :lfs_object_state, autosave: false, inverse_of: :lfs_object, class_name: 'Geo::LfsObjectState'

      scope :project_id_in, ->(ids) { joins(:projects).merge(::Project.id_in(ids)) }

      def verification_state_object
        lfs_object_state
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of lfs_objects based on the query given in `query`.
      #
      # @param [String] query term that will search over lfs_object :file attribute
      #
      # @return [ActiveRecord::Relation<LfsObject>] a collection of LFS objects
      def search(query)
        return all if query.empty?

        where(sanitize_sql_for_conditions({ file: query })).limit(1000)
      end

      # @return [ActiveRecord::Relation<LfsObject>] scope observing selective
      #         sync settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        primary_key_in = params[:primary_key_in].presence
        replicables = replicables.primary_key_in(primary_key_in) if primary_key_in

        return replicables unless node.selective_sync?

        lfs_object_projects = LfsObjectsProject.project_id_in(::Project.selective_sync_scope(node))
        lfs_object_projects = lfs_object_projects.where(lfs_object_id: primary_key_in) if primary_key_in

        replicables.where(id: lfs_object_projects.select(:lfs_object_id).distinct)
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::LfsObjectState
      end
    end

    def lfs_object_state
      super || build_lfs_object_state
    end
  end
end

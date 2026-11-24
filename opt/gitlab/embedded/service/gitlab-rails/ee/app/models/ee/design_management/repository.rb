# frozen_string_literal: true

module EE
  module DesignManagement
    module Repository
      extend ActiveSupport::Concern

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :design_management_repository_state)

        with_replicator Geo::DesignManagementRepositoryReplicator

        has_one :design_management_repository_state,
          autosave: false,
          inverse_of: :design_management_repository,
          class_name: 'Geo::DesignManagementRepositoryState',
          foreign_key: 'design_management_repository_id'

        scope :project_id_in, ->(ids) { where(project_id: ids) }
      end

      def verification_state_object
        design_management_repository_state
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        # @return [ActiveRecord::Relation<LfsObject>] scope observing selective
        #         sync settings of the given node
        override :selective_sync_scope
        def selective_sync_scope(node, **params)
          replicables = params.fetch(:replicables, all)
          replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

          return replicables unless node.selective_sync?

          replicables_project_ids = replicables.distinct.pluck(:project_id)

          selective_projects_ids  =
            ::Project.selective_sync_scope(node)
              .id_in(replicables_project_ids)
              .pluck_primary_key

          replicables.project_id_in(selective_projects_ids)
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::DesignManagementRepositoryState
        end
      end

      # Geo checks this method in FrameworkRepositorySyncService to avoid
      # snapshotting repositories using object pools
      def pool_repository
        nil
      end

      def design_management_repository_state
        super || build_design_management_repository_state
      end
    end
  end
end

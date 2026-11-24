# frozen_string_literal: true

module EE
  # ProjectRepository EE mixin
  #
  # This module is intended to encapsulate EE-specific model logic
  # and be prepended in the `ProjectRepository` model
  module ProjectRepository # rubocop:disable Gitlab/BoundedContexts -- EE module for existing model
    extend ActiveSupport::Concern

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel

      with_replicator Geo::ProjectRepositoryReplicator

      has_one :project_repository_state,
        autosave: false,
        inverse_of: :project_repository,
        foreign_key: :project_repository_id,
        class_name: 'Geo::ProjectRepositoryState'

      # Delegate repository-related methods to the associated project
      delegate(
        :repository,
        :repository_storage,
        to: :project)

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS,
        to: :project_repository_state)

      def verification_state_object
        project_repository_state
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # @return [ActiveRecord::Relation<ProjectRepository>] scope observing selective sync
      #         settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

        return replicables unless node.selective_sync?

        replicables.where(project_id: ::Project.selective_sync_scope(node).select(:id))
      end

      override :verification_state_table_class
      def verification_state_table_class
        ::Geo::ProjectRepositoryState
      end

      override :verification_state_model_key
      def verification_state_model_key
        :project_repository_id
      end

      override :create_verification_details_for
      def create_verification_details_for(primary_keys)
        keys_with_existing_states = pluck_verification_details_ids_in_range(primary_keys)

        # To avoid duplicates in the absence of a UNIQUE constraint, we filter out records with an existing state
        # This is not perfect, as a record with a PK could have been added between the SELECT and UPDATE below.
        # However, this method is only used by the VerificationStateBackfillService, so as long as the FF is off, even
        # after https://gitlab.com/gitlab-org/gitlab/-/merge_requests/223027 is merged, it will not get called
        # for this model.
        rows = primary_key_in(primary_keys - keys_with_existing_states).map do |project_repo|
          { verification_state_model_key => project_repo.id, :project_id => project_repo.project_id }
        end

        # TODO: use `unique_by: :project_repository_id` once the database constraint on project_repository_id is added
        # See https://gitlab.com/gitlab-org/gitlab/-/work_items/590458
        verification_state_table_class.insert_all(rows)
      end
    end

    def project_repository_state
      super || build_project_repository_state
    end
  end # rubocop:enable Gitlab/BoundedContexts
end

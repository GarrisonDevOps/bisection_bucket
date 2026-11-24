# frozen_string_literal: true

module EE
  module Terraform
    module StateVersion
      extend ActiveSupport::Concern

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel
        include ::Geo::VerificationStateDefinition

        with_replicator ::Geo::TerraformStateVersionReplicator

        has_one :terraform_state_version_state,
          class_name: 'Geo::TerraformStateVersionState',
          foreign_key: :terraform_state_version_id,
          inverse_of: :terraform_state_version,
          autosave: false

        scope :project_id_in, ->(ids) { joins(:terraform_state).where('terraform_states.project_id': ids) }

        scope :for_state_uuid_and_version, ->(uuid, version) {
          joins(:terraform_state).where(terraform_states: { uuid: uuid }, version: version)
        }

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :terraform_state_version_state)

        scope :available_verifiables, -> { joins(:terraform_state_version_state) }

        def verification_state_object
          terraform_state_version_state
        end

        def terraform_state_version_state
          state = super || build_terraform_state_version_state
          state.terraform_state_version_id ||= id if id.present?
          state.terraform_state_version ||= self
          state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        # Search for a list of terraform_state_versions based on the query given in `query`.
        #
        # @param [String] query term that will search over :file attribute
        #
        # @return [ActiveRecord::Relation<Terraform::StateVersion>] a collection of terraform state versions
        def search(query)
          return all if query.empty?

          # The current file format for terraform state versions
          # uses the following structure: <version or uuid>.tfstate
          where(sanitize_sql_for_conditions({ file: "#{query}.tfstate" })).limit(1000)
        end

        override :selective_sync_scope
        def selective_sync_scope(node, **params)
          replicables = params.fetch(:replicables, all)
          replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

          return replicables unless node.selective_sync?

          replicables.project_id_in(::Project.selective_sync_scope(node).select(:id))
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::TerraformStateVersionState
        end

        override :verification_state_model_key
        def verification_state_model_key
          :terraform_state_version_id
        end
      end
    end
  end
end

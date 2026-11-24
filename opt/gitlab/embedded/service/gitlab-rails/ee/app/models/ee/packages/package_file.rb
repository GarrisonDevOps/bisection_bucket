# frozen_string_literal: true

module EE
  module Packages
    module PackageFile
      extend ActiveSupport::Concern

      EE_SEARCHABLE_ATTRIBUTES = %i[file_name].freeze

      prepended do
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel
        include ::Geo::VerificationStateDefinition
        include ::Gitlab::SQL::Pattern

        with_replicator ::Geo::PackageFileReplicator

        has_one :package_file_state,
          autosave: false,
          inverse_of: :package_file,
          foreign_key: :package_file_id,
          class_name: '::Geo::PackageFileState'

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :package_file_state)

        scope :available_verifiables, -> { joins(:package_file_state) }
        def verification_state_object
          package_file_state
        end

        def package_file_state
          state = super || build_package_file_state
          state.package_file_id ||= id if id.present?
          state.package_file ||= self
          state
        end
      end

      class_methods do
        extend ::Gitlab::Utils::Override

        # Search for a list of package_files based on the query given in `query`.
        #
        # @param [String] query term that will search over package_file :file_name
        #
        # @return [ActiveRecord::Relation<Packages::PackageFile>] a collection of package files
        def search(query)
          return all if query.empty?

          fuzzy_search(query, EE_SEARCHABLE_ATTRIBUTES).limit(500)
        end

        override :selective_sync_scope
        def selective_sync_scope(node, **params)
          replicables = params.fetch(:replicables, all)
          replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

          return replicables unless node.selective_sync?

          replicables
            .joins(:package)
            .where(packages_packages: { project_id: ::Project.selective_sync_scope(node).select(:id) })
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::PackageFileState
        end

        override :verification_state_model_key
        def verification_state_model_key
          :package_file_id
        end
      end
    end
  end
end

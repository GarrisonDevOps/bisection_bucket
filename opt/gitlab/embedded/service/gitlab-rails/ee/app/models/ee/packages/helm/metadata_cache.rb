# frozen_string_literal: true

module EE
  module Packages
    module Helm
      module MetadataCache
        extend ActiveSupport::Concern

        prepended do
          include ::Geo::ReplicableModel
          include ::Geo::VerifiableModel

          delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :packages_helm_metadata_cache_state)

          with_replicator Geo::PackagesHelmMetadataCacheReplicator

          has_one :packages_helm_metadata_cache_state,
            autosave: false,
            inverse_of: :packages_helm_metadata_cache,
            class_name: 'Geo::PackagesHelmMetadataCacheState'

          scope :available_verifiables, -> { joins(:packages_helm_metadata_cache_state) }

          scope :with_object_storage_key, ->(key) { where(object_storage_key: key) }

          def verification_state_object
            packages_helm_metadata_cache_state
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :selective_sync_scope
          def selective_sync_scope(node, **params)
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

            return replicables unless node.selective_sync?

            replicables.where(project_id: ::Project.selective_sync_scope(node).select(:id))
          end

          override :verification_state_model_key
          def verification_state_model_key
            :packages_helm_metadata_cache_id
          end

          override :verification_state_table_class
          def verification_state_table_class
            ::Geo::PackagesHelmMetadataCacheState
          end
        end

        def packages_helm_metadata_cache_state
          super || build_packages_helm_metadata_cache_state
        end
      end
    end
  end
end

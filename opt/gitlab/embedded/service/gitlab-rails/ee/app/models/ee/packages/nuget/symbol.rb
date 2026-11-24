# frozen_string_literal: true

module EE
  module Packages
    module Nuget
      module Symbol
        extend ActiveSupport::Concern

        prepended do
          include ::Geo::ReplicableModel
          include ::Geo::VerifiableModel

          delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :packages_nuget_symbol_state)

          with_replicator Geo::PackagesNugetSymbolReplicator

          has_one :packages_nuget_symbol_state, autosave: false, inverse_of: :packages_nuget_symbol,
            class_name: 'Geo::PackagesNugetSymbolState'

          after_save :save_verification_details

          scope :project_id_in, ->(ids) { where(project_id: ids) }
          scope :with_object_storage_key, ->(key) { where(object_storage_key: key) }

          def verification_state_object
            packages_nuget_symbol_state
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :verification_state_model_key
          def verification_state_model_key
            :packages_nuget_symbol_id
          end

          override :verification_state_table_class
          def verification_state_table_class
            ::Geo::PackagesNugetSymbolState
          end

          # @return [ActiveRecord::Relation<Packages::Nuget::Symbol>] scope observing selective sync settings
          # of the given node
          override :selective_sync_scope
          def selective_sync_scope(node, **params)
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            replicables.project_id_in(::Project.selective_sync_scope(node).select(:id))
          end
        end

        def packages_nuget_symbol_state
          super || build_packages_nuget_symbol_state
        end
      end
    end
  end
end

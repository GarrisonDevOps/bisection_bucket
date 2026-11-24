# frozen_string_literal: true

module EE
  module Packages
    module Debian
      module ProjectComponentFile
        extend ActiveSupport::Concern

        prepended do
          include ::Geo::ReplicableModel
          include ::Geo::VerifiableModel

          delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :packages_debian_project_component_file_state)

          with_replicator Geo::PackagesDebianProjectComponentFileReplicator

          has_one :packages_debian_project_component_file_state,
            autosave: false,
            inverse_of: :packages_debian_project_component_file,
            class_name: 'Geo::PackagesDebianProjectComponentFileState'

          scope :project_id_in, ->(ids) { where(project_id: ids) }

          def verification_state_object
            packages_debian_project_component_file_state
          end
        end

        class_methods do
          extend ::Gitlab::Utils::Override

          override :verification_state_model_key
          def verification_state_model_key
            :packages_debian_project_component_file_id
          end

          override :verification_state_table_class
          def verification_state_table_class
            ::Geo::PackagesDebianProjectComponentFileState
          end

          override :create_verification_details_for
          def create_verification_details_for(primary_keys)
            # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by primary_keys array
            project_id_values = where(id: primary_keys).pluck(:id, :project_id).to_h
            # rubocop:enable Database/AvoidUsingPluckWithoutLimit

            rows = primary_keys.map do |id|
              { verification_state_model_key => id, project_id: project_id_values.fetch(id) }
            end

            verification_state_table_class.insert_all(rows)
          end

          # @return [ActiveRecord::Relation<Packages::Debian::ProjectComponentFile>]
          #   scope observing selective sync settings of the given node
          override :selective_sync_scope
          def selective_sync_scope(node, **params)
            replicables = params.fetch(:replicables, all)
            replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

            return replicables unless node.selective_sync?

            replicables.project_id_in(::Project.selective_sync_scope(node).select(:id))
          end
        end

        def packages_debian_project_component_file_state
          super || build_packages_debian_project_component_file_state
        end
      end
    end
  end
end

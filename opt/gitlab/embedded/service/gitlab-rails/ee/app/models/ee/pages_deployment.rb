# frozen_string_literal: true

module EE
  module PagesDeployment
    EE_SEARCHABLE_ATTRIBUTES = %i[file].freeze

    extend ActiveSupport::Concern

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel
      include ::Gitlab::SQL::Pattern

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :pages_deployment_state)

      with_replicator ::Geo::PagesDeploymentReplicator

      has_one :pages_deployment_state, autosave: false, inverse_of: :pages_deployment, class_name: '::Geo::PagesDeploymentState'

      def verification_state_object
        pages_deployment_state
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of pages_deployments based on the query given in `query`.
      #
      # @param [String] query term that will search over :file attribute
      #
      # @return [ActiveRecord::Relation<PagesDeployment>] a collection of pages deployments
      def search(query)
        return all if query.empty?

        fuzzy_search(query, EE_SEARCHABLE_ATTRIBUTES)
      end

      # @return [ActiveRecord::Relation<PagesDeployment>] scope observing selective sync settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].presence

        return replicables unless node.selective_sync?

        replicables.project_id_in(::Project.selective_sync_scope(node))
      end

      override :verification_state_table_class
      def verification_state_table_class
        ::Geo::PagesDeploymentState
      end
    end

    def pages_deployment_state
      super || build_pages_deployment_state
    end
  end
end

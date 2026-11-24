# frozen_string_literal: true

module EE
  module SnippetRepository
    extend ActiveSupport::Concern

    EE_SEARCHABLE_ATTRIBUTES = %i[disk_path].freeze

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel
      include ::Geo::VerificationStateDefinition
      include FromUnion
      include ::Gitlab::SQL::Pattern

      with_replicator ::Geo::SnippetRepositoryReplicator

      has_one :snippet_repository_state,
        autosave: false,
        inverse_of: :snippet_repository,
        foreign_key: :snippet_repository_id,
        class_name: '::Geo::SnippetRepositoryState'

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :snippet_repository_state)

      scope :available_verifiables, -> { joins(:snippet_repository_state) }

      def verification_state_object
        snippet_repository_state
      end

      def snippet_repository_state
        state = super || build_snippet_repository_state
        state.snippet_repository_id ||= id if id.present?
        state.snippet_repository ||= self
        state
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of snippet_repositories based on the query given in `query`.
      #
      # @param [String] query term that will search over snippet_repositories :disk_path attribute
      #
      # @return [ActiveRecord::Relation<SnippetRepository>] a collection of snippet repositories
      def search(query)
        return all if query.empty?

        fuzzy_search(query, EE_SEARCHABLE_ATTRIBUTES)
      end

      # @return [ActiveRecord::Relation<SnippetRepository>] scope observing selective sync
      #          settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables    = params.fetch(:replicables, all)
        primary_key_in = params[:primary_key_in].presence
        replicables    = replicables.primary_key_in(primary_key_in) if primary_key_in

        return replicables unless node.selective_sync?

        if node.selective_sync_by_namespaces?
          snippet_repositories_for_selected_namespaces(node, replicables)
        elsif node.selective_sync_by_organizations?
          snippet_repositories_for_selected_organizations(node, replicables)
        elsif node.selective_sync_by_shards?
          snippet_repositories_for_selected_shards(node, replicables)
        else
          raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
        end
      end

      def snippet_repositories_for_selected_namespaces(node, replicables)
        personal_snippet_repositories = snippet_repositories_for_personal_snippets(replicables)

        selected_project_ids = ::Project.selective_sync_scope(node).select(:id)
        project_snippet_repositories =
          project_snippets_repositories_for_projects(replicables, selected_project_ids)

        self.from_union([project_snippet_repositories, personal_snippet_repositories])
      end

      def snippet_repositories_for_selected_organizations(node, replicables)
        selected_organization_ids = node.organizations.pluck_primary_key.presence

        personal_snippet_repositories =
          snippet_repositories_for_personal_snippets(replicables, selected_organization_ids)

        selected_project_ids = ::Project.selective_sync_scope(node).select(:id)

        project_snippet_repositories =
          project_snippets_repositories_for_projects(replicables, selected_project_ids)

        self.from_union([project_snippet_repositories, personal_snippet_repositories])
      end

      def snippet_repositories_for_personal_snippets(replicables, organization_ids = nil)
        personal_snippets = ::Snippet.only_personal_snippets
        personal_snippets = personal_snippets.where(organization_id: organization_ids) if organization_ids

        replicables.joins(:snippet).where(snippet: personal_snippets)
      end

      def project_snippets_repositories_for_projects(replicables, project_ids)
        replicables
          .joins(snippet: :project)
          .merge(::Snippet.for_projects(project_ids))
      end

      def snippet_repositories_for_selected_shards(node, replicables)
        replicables.for_repository_storage(node.selective_sync_shards)
      end

      override :verification_state_table_class
      def verification_state_table_class
        Geo::SnippetRepositoryState
      end

      override :verification_state_model_key
      def verification_state_model_key
        :snippet_repository_id
      end
    end
  end
end

# frozen_string_literal: true

module EE
  module ContainerRepository
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::StrongMemoize

    GITLAB_ORG_NAMESPACE = 'gitlab-org'
    EE_SEARCHABLE_ATTRIBUTES = %i[name].freeze

    prepended do
      include ::Geo::ReplicableModel
      include ::Geo::VerifiableModel

      delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :container_repository_state)

      with_replicator ::Geo::ContainerRepositoryReplicator

      scope :project_id_in, ->(ids) { where(project_id: ids) }

      has_one :container_repository_state, autosave: false, inverse_of: :container_repository, class_name: 'Geo::ContainerRepositoryState'

      def verification_state_object
        container_repository_state
      end
    end

    class_methods do
      extend ::Gitlab::Utils::Override

      # Search for a list of container_repositories based on the query given in `query`.
      #
      # @param [String] query term that will search over container_repository :name attribute
      #
      # @return [ActiveRecord::Relation<ContainerRepository>] a collection of container repositories
      def search(query)
        return all if query.empty?

        fuzzy_search(query, EE_SEARCHABLE_ATTRIBUTES)
      end

      # @param primary_key_in [Range, ContainerRepository] arg to pass to primary_key_in scope
      # @return [ActiveRecord::Relation<ContainerRepository>] everything that should be synced
      #         to this node, restricted by primary key
      override :replicables_for_current_secondary
      def replicables_for_current_secondary(primary_key_in)
        return none unless replicator_class.replication_enabled?

        super
      end

      override :verification_state_table_class
      def verification_state_table_class
        ::Geo::ContainerRepositoryState
      end

      # @return [ActiveRecord::Relation<ContainerRepository>] scope observing selective sync settings of the given node
      override :selective_sync_scope
      def selective_sync_scope(node, **params)
        replicables = params.fetch(:replicables, all)
        replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

        return replicables unless node.selective_sync?

        replicables.project_id_in(::Project.selective_sync_scope(node))
      end
    end

    def container_repository_state
      super || build_container_repository_state
    end

    def push_blob(digest, blob_io, size)
      client.push_blob(path, digest, blob_io, size)
    end

    def push_manifest(tag, manifest, manifest_type)
      client.push_manifest(path, tag, manifest, manifest_type)
    end

    def blob_exists?(digest)
      client.blob_exists?(path, digest)
    end

    def manifest_exists?(reference)
      client.manifest_exists?(path, reference)
    end

    # @return [String] a checksum value used for verifying correct replication
    def tag_list_digest
      tag_list = tags.map do |tag|
        [tag.name, tag.digest]
      end

      tag_list.sort_by!(&:first)
      tag_list_str = tag_list.map(&:join).join

      ::Digest::SHA256.hexdigest(tag_list_str)
    end
    strong_memoize_attr :tag_list_digest

    override :protected_from_delete_by_tag_rules?
    def protected_from_delete_by_tag_rules?(user)
      return true unless user
      return true if immutable_tag_rules_apply?

      super
    end

    private

    def immutable_tag_rules_apply?
      return false unless project.licensed_feature_available?(:container_registry_immutable_tag_rules)
      return false unless project.has_container_registry_immutable_tag_rules?

      has_tags?
    end
  end
end

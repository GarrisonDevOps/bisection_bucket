# frozen_string_literal: true

class GroupWikiRepository < ApplicationRecord
  extend ::Gitlab::Utils::Override
  include ::Geo::ReplicableModel
  include ::Geo::VerifiableModel
  include Shardable

  with_replicator Geo::GroupWikiRepositoryReplicator

  belongs_to :group

  has_one :group_wiki_repository_state,
    class_name: 'Geo::GroupWikiRepositoryState',
    inverse_of: :group_wiki_repository,
    autosave: false

  validates :group, :disk_path, presence: true, uniqueness: true

  delegate :create_wiki, :repository_storage, to: :group
  delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :group_wiki_repository_state)

  # @return [ActiveRecord::Relation<GroupWikiRepository>] scope observing selective sync
  #          settings of the given node
  override :selective_sync_scope
  def self.selective_sync_scope(node, **params)
    replicables = params.fetch(:replicables, all)
    replicables = replicables.primary_key_in(params[:primary_key_in]) if params[:primary_key_in].present?

    return replicables unless node.selective_sync?

    if node.selective_sync_by_namespaces? || node.selective_sync_by_organizations?
      replicables.group_wiki_repositories_for_selected_namespaces(node)
    elsif node.selective_sync_by_shards?
      replicables.group_wiki_repositories_for_selected_shards(node)
    else
      raise ::Geo::Errors::UnknownSelectiveSyncType.new(selective_sync_type: node.selective_sync_type)
    end
  end

  def self.group_wiki_repositories_for_selected_namespaces(node)
    joins(:group).where(group_id: node.namespaces_for_group_owned_replicables.select(:id))
  end

  def self.group_wiki_repositories_for_selected_shards(node)
    for_repository_storage(node.selective_sync_shards)
  end

  override :verification_state_table_class
  def self.verification_state_table_class
    ::Geo::GroupWikiRepositoryState
  end

  override :verification_state_model_key
  def self.verification_state_model_key
    :group_wiki_repository_id
  end

  def group_wiki_repository_state
    super || build_group_wiki_repository_state
  end

  # Geo checks this method in FrameworkRepositorySyncService to avoid
  # snapshotting repositories using object pools
  def pool_repository
    nil
  end

  def repository
    group.wiki.repository
  end

  def verification_state_object
    group_wiki_repository_state
  end
end

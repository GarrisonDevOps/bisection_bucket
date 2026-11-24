# frozen_string_literal: true

module Search
  module Zoekt
    class Replica < ApplicationRecord
      include NamespaceValidateable

      self.table_name = 'zoekt_replicas'

      enum :state, {
        pending: 0,
        ready: 10
      }

      belongs_to :zoekt_enabled_namespace, inverse_of: :replicas, class_name: '::Search::Zoekt::EnabledNamespace'

      has_many :indices, foreign_key: :zoekt_replica_id, inverse_of: :replica

      validate :project_can_not_assigned_to_same_replica_unless_index_is_reallocating

      scope :preload_nodes, -> { includes(indices: :node) }

      scope :with_all_ready_indices, -> do
        raw_sql = 'sum(case when zoekt_indices.state != :state then 0 else 1 end) = count(*)'
        joins(:indices).group(:id).having(raw_sql, state: Search::Zoekt::Index.states[:ready])
      end

      scope :with_non_ready_indices, -> do
        non_ready_index_states = Search::Zoekt::Index.states.values - [Search::Zoekt::Index.states[:ready]]
        where(id: Search::Zoekt::Index.select(:zoekt_replica_id).where(state: non_ready_index_states).distinct)
      end

      scope :for_namespace, ->(id) { where(namespace_id: id) }
      scope :without_indices, -> { left_joins(:indices).where(zoekt_indices: { zoekt_replica_id: nil }) }

      def self.for_enabled_namespace!(zoekt_enabled_namespace)
        params = {
          namespace_id: zoekt_enabled_namespace.root_namespace_id,
          zoekt_enabled_namespace_id: zoekt_enabled_namespace.id
        }

        where(namespace_id: params[:namespace_id]).first || create!(params)
      rescue ActiveRecord::RecordInvalid => invalid
        retry if invalid.record&.errors&.of_kind?(:namespace_id, :taken)
      end

      def self.search_enabled?(namespace_id)
        joins(:zoekt_enabled_namespace, indices: :node)
          .where(zoekt_enabled_namespace: { search: true })
          .merge(Search::Zoekt::Node.for_search.searchable)
          .for_namespace(namespace_id)
          .ready
          .exists?
      end

      def fetch_repositories_with_project_identifier(project_id)
        Repository.for_replica_id(id).for_project_id(project_id)
      end

      private

      def project_can_not_assigned_to_same_replica_unless_index_is_reallocating
        return unless indices.joins(:zoekt_repositories).where.not(zoekt_repositories: { project_id: nil })
          .where.not(state: :reallocating).group('zoekt_repositories.project_id')
          .having('count(zoekt_indices.id) > 1').exists?

        errors.add(:base, 'A project can not be assigned to the same replica unless the index is being reallocated')
      end
    end
  end
end

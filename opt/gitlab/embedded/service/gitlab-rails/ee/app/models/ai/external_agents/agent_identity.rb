# frozen_string_literal: true

module Ai
  module ExternalAgents
    class AgentIdentity < ApplicationRecord
      AGENT_TYPES = %w[claude-code opencode cursor codex].freeze
      LAST_SYNCED_AT_INTERVAL = 5.minutes
      # An unrevoked identity that synced within this period is active, otherwise inactive. An
      # identity that has not synced yet counts from when it was registered.
      ACTIVE_PERIOD = 30.days

      self.table_name = 'ai_agent_identities'

      belongs_to :user
      belongs_to :project

      validates :agent_type, presence: true, inclusion: { in: AGENT_TYPES }
      validates :machine_fingerprint, presence: true,
        format: { with: /\A\h{64}\z/, message: 'must be a 64-character hex string' }

      scope :active, -> { where(revoked_at: nil) }
      scope :revoked, -> { where.not(revoked_at: nil) }
      scope :for_project, ->(project) { where(project: project) }
      scope :for_user, ->(user) { where(user: user) }
      scope :in_namespace_hierarchy, ->(namespace) {
        where(project_id: ::Project.in_namespace(namespace.self_and_descendants.select(:id)).select(:id))
      }
      scope :with_agent_types, ->(agent_types) { where(agent_type: agent_types) }
      scope :recently_active, -> { active.where(last_active_at.gteq(ACTIVE_PERIOD.ago)) }
      scope :not_recently_active, -> { active.where(last_active_at.lt(ACTIVE_PERIOD.ago)) }
      scope :order_by_last_synced_desc, -> {
        order(::Gitlab::Pagination::Keyset::Order.build([
          ::Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: 'last_synced_at',
            column_expression: arel_table[:last_synced_at],
            order_expression: arel_table[:last_synced_at].desc.nulls_last,
            reversed_order_expression: arel_table[:last_synced_at].asc.nulls_first,
            order_direction: :desc,
            nullable: :nulls_last
          ),
          ::Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: 'id',
            order_expression: arel_table[:id].desc
          )
        ]))
      }

      # [agent_type, machines, unrevoked machines, distinct users] per type,
      # most machines first.
      def self.registration_counts_by_agent_type(limit:)
        group(:agent_type)
          .order(Arel.sql('COUNT(*) DESC'), agent_type: :asc)
          .limit(limit)
          .pluck(
            :agent_type,
            Arel.sql('COUNT(*)'),
            Arel.sql('COUNT(*) FILTER (WHERE revoked_at IS NULL)'),
            Arel.sql('COUNT(DISTINCT user_id)')
          )
      end

      def self.last_active_at
        Arel::Nodes::NamedFunction.new('COALESCE', [arel_table[:last_synced_at], arel_table[:created_at]])
      end

      def self.register(user:, project:, agent_type:, machine_fingerprint:)
        safe_find_or_create_by!( # rubocop:disable Performance/ActiveRecordSubtransactionMethods -- identity registration is low-traffic and write-once per machine per project
          user: user,
          project: project,
          agent_type: agent_type,
          machine_fingerprint: machine_fingerprint
        )
      end

      # Clients call several endpoints on every sync, so the write is throttled and
      # skips updated_at, which tracks changes to the identity itself.
      def self.record_sync(id)
        return if id.blank?

        active
          .where(id: id)
          .where('last_synced_at IS NULL OR last_synced_at < ?', LAST_SYNCED_AT_INTERVAL.ago)
          .update_all(last_synced_at: Time.current)
      end

      def self.owned_by?(id:, user:, project:, agent_type:)
        active.where(id: id, user: user, project: project, agent_type: agent_type).exists?
      end

      def revoked?
        revoked_at.present?
      end

      def status
        return :revoked if revoked?
        return :active if (last_synced_at || created_at) >= ACTIVE_PERIOD.ago

        :inactive
      end

      def revoke!
        update!(revoked_at: Time.current)
      end
    end
  end
end

# frozen_string_literal: true

module Ai
  module Catalog
    class ItemConsumer < ApplicationRecord
      include AfterCommitQueue
      include FromUnion

      PINNED_VERSION_PREFIX_REGEX = /\A[1-9]\d*\.(0|[1-9]\d*)\.(0|[1-9]\d*)\z/

      ignore_column :organization_id, remove_with: '19.7', remove_after: '2026-12-18'

      self.table_name = "ai_catalog_item_consumers"

      enum :kind, { direct: 0, inheritance: 1 }

      validates :enabled, :locked, inclusion: { in: [true, false] }

      validates :pinned_version_prefix, length: { maximum: 50 },
        format: { with: PINNED_VERSION_PREFIX_REGEX, message: ->(*) { s_('AICatalog|must be in the format "n.n.n"') } },
        allow_nil: true

      validates_with ExactlyOnePresentValidator, fields: :sharding_keys,
        message: ->(_fields) {
          s_('AICatalog|An agent or flow can only be enabled once per group or project')
        }
      validate :validate_organization_match
      validate :validate_item_privacy_allowed, if: :item_changed?
      validate :validate_item_allowed_by_namespace_restriction, if: :item_changed?
      validate :validate_service_account, if: :service_account_id?
      validate :validate_parent_item_consumer, if: :parent_item_consumer_id?
      validate :validate_item_uniqueness
      validate :validate_kind_unchanged, on: :update
      validate :validate_inheritance_requires_top_level_group, if: :inheritance?
      validate :validate_inheritance_item_visibility, if: :inheritance?

      belongs_to :item, class_name: 'Ai::Catalog::Item',
        foreign_key: :ai_catalog_item_id, inverse_of: :consumers, optional: false

      belongs_to :group
      belongs_to :project
      belongs_to :parent_item_consumer, class_name: 'Ai::Catalog::ItemConsumer'
      belongs_to :service_account, class_name: 'User'

      has_one :flow_trigger, class_name: 'Ai::FlowTrigger', inverse_of: :ai_catalog_item_consumer

      has_many :child_item_consumers, class_name: 'Ai::Catalog::ItemConsumer', inverse_of: :parent_item_consumer

      has_many(
        :child_item_consumers_flow_triggers,
        class_name: 'Ai::FlowTrigger', source: :flow_trigger, through: :child_item_consumers
      )

      validates :service_account, absence: true, unless: -> { item&.flow? || item&.third_party_flow? }
      validates :service_account, presence: true, on: :create, if: :service_account_required?
      validates :service_account, uniqueness: true, allow_nil: true

      scope :by_enabled, ->(enabled) { where(enabled: enabled) }

      accepts_nested_attributes_for :flow_trigger

      scope :not_for_projects, ->(project) { where.not(project: project).or(where(project: nil)) }
      scope :for_projects, ->(projects) { where(project: projects) }
      scope :for_groups, ->(groups) { where(group: groups) }

      scope :for_container_item_pairs, ->(container_type, container_item_pairs) do
        raise ArgumentError, "Unknown container_type: #{container_type}" unless container_type.in?([:project, :group])

        columns = [:"#{container_type}_id", :ai_catalog_item_id]
        where(columns => container_item_pairs)
      end

      scope :for_item, ->(item_id) { where(ai_catalog_item_id: item_id) }
      scope :with_item_type, ->(item_type) { joins(:item).where(item: { item_type: item_type }) }
      scope :with_items, -> { includes(:item) }
      scope :with_items_and_latest_versions, -> { includes(item: :latest_version) }

      scope :excluding_custom_agents, -> do
        foundational_ids = Ai::Catalog::Item.foundational_chat_agent_ids

        joins(:item)
          .where(ai_catalog_item_id: foundational_ids)
          .or(joins(:item).where.not(item: { item_type: :agent }))
      end

      scope :excluding_custom_flows, -> do
        joins(:item).where.not(item: { item_type: :flow, foundational_flow_reference: nil })
      end

      scope :excluding_foundational_flows, -> do
        joins(:item).where(item: { foundational_flow_reference: nil })
      end

      scope :excluding_external_agents, -> do
        joins(:item).where.not(item: { item_type: :third_party_flow })
      end

      class << self
        def pluck_item_ids(limit)
          limit(limit).pluck(:ai_catalog_item_id)
        end

        def find_by_project_and_flow_reference(project, flow_reference)
          joins(:item)
            .where(project: project)
            .where(ai_catalog_items: { foundational_flow_reference: flow_reference })
            .first
        end

        def any_outside_group_hierarchy?(root_group)
          hierarchy_project_ids = root_group.all_projects.select(:id)
          hierarchy_group_ids = root_group.self_and_descendants.select(:id)

          where.not(project_id: hierarchy_project_ids)
            .or(where.not(group_id: hierarchy_group_ids))
            .any?
        end

        def with_priority_ordering(current_user)
          return reorder(id: :desc) if current_user.blank?

          items_table = Ai::Catalog::Item.arel_table.alias('item')
          pa_table = ProjectAuthorization.arel_table

          relation = join_item_table(all, items_table)

          pa_join = arel_table
            .join(pa_table, Arel::Nodes::OuterJoin)
            .on(
              pa_table[:project_id].eq(items_table[:project_id])
                .and(pa_table[:user_id].eq(current_user.id))
            )

          priority_case = build_consumer_priority_case(items_table, pa_table)
          order_columns = build_keyset_order_columns(priority_case)

          relation
            .joins(pa_join.join_sources)
            .select(arel_table[Arel.star], priority_case.as('consumer_priority'))
            .reorder(Gitlab::Pagination::Keyset::Order.build(order_columns))
        end

        def with_usage_ordering(direction)
          items_table = Ai::Catalog::Item.arel_table.alias('item')
          usage_column = items_table[:last_30_day_usage_count]

          relation = join_item_table(all, items_table)

          order_columns = build_usage_order_columns(usage_column, direction)

          # Select the ordered column so it is present on every page, including the
          # first (uncursored) one. add_to_projections only fires on cursored pages,
          # so without this the endCursor would carry a nil usage value and page two
          # would filter out every row.
          relation
            .select(arel_table[Arel.star], usage_column.as('last_30_day_usage_count'))
            .reorder(Gitlab::Pagination::Keyset::Order.build(order_columns))
        end

        private

        # Guard against double-joining when the caller already added .joins(:item).
        def join_item_table(relation, items_table)
          return relation if relation.joins_values.include?(:item)

          item_join = arel_table.join(items_table).on(
            items_table[:id].eq(arel_table[:ai_catalog_item_id])
          )
          relation.joins(item_join.join_sources)
        end

        def build_usage_order_columns(usage_column, direction)
          [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'last_30_day_usage_count',
              column_expression: usage_column,
              order_expression: direction == :asc ? usage_column.asc : usage_column.desc,
              nullable: :not_nullable,
              order_direction: direction,
              add_to_projections: false
            ),
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'id',
              order_expression: direction == :asc ? arel_table[:id].asc : arel_table[:id].desc,
              nullable: :not_nullable,
              order_direction: direction
            )
          ]
        end

        # Builds an Arel CASE expression to determine consumer display priority.
        #
        # Priority order:
        # 1. Foundational chat agents and external agents (SaaS only) - matched by hardcoded IDs
        # 2. Foundational flows and external agents (non-SaaS) - identified by verification_level
        #    set to gitlab_maintained (100). On non-SaaS, foundational chat agents are not stored
        #    in the catalog, so they are excluded. However, external agents are created with
        #    verification_level = gitlab_maintained, so they are prioritized through this condition.
        # 3. Items from the user's own projects - determined by access_level from project_authorizations
        # 4. All remaining items
        def build_consumer_priority_case(items_table, pa_table)
          gitlab_maintained = Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained]

          priority = Arel::Nodes::Case.new

          chat_agent_ids = Ai::Catalog::Item.foundational_chat_agent_ids
          external_agent_ids = Ai::Catalog::Item.foundational_external_agent_ids

          priority = priority.when(items_table[:id].in(chat_agent_ids)).then(1) if chat_agent_ids.present?
          priority = priority.when(items_table[:id].in(external_agent_ids)).then(2) if external_agent_ids.present?

          priority
            .when(items_table[:verification_level].eq(gitlab_maintained)).then(3)
            .when(pa_table[:access_level].not_eq(nil)).then(4)
            .else(5)
        end

        def build_keyset_order_columns(priority_case)
          [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'consumer_priority',
              column_expression: priority_case,
              order_expression: priority_case.asc,
              nullable: :not_nullable,
              order_direction: :asc,
              add_to_projections: false
            ),
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'id',
              order_expression: arel_table[:id].desc,
              nullable: :not_nullable
            )
          ]
        end
      end

      scope :for_catalog_items, ->(item_ids) { where(ai_catalog_item_id: item_ids) }
      scope :for_service_account, ->(service_account_id) { where(service_account_id:) }
      scope :with_service_account, -> { preload(:service_account) }
      scope :for_groups_with_service_account, ->(groups) { for_groups(groups).where.not(service_account_id: nil) }
      scope :inherited_with_service_account_for, ->(root_groups) {
        inheritance.for_groups_with_service_account(root_groups)
      }
      scope :with_parent_on_groups, ->(groups) {
        where(parent_item_consumer_id: unscoped.for_groups(groups).select(:id))
      }
      scope :with_any_child_item_consumers, -> {
        children = arel_table.alias('children')
        where(
          unscoped.from(children).select(Arel.sql('1'))
            .where(children[:parent_item_consumer_id].eq(arel_table[:id])).arel.exists
        )
      }
      scope :with_items_configurable_for_project, ->(project_id) {
        joins(:item).where(item: { visibility: :public }).or(where(item: { project_id: project_id }))
      }

      scope :with_synthesized_foundational_agent_consumers, ->(for_container, item_consumer_attributes) {
        query_with_synthesized_foundational_agents(for_container, item_consumer_attributes)
      }

      def container
        project || group
      end

      def root_ancestor
        container.root_ancestor
      end

      # Use as the subject for read and execute checks, so inheritance records are checked against the project.
      def authorization_subject(project:)
        return self unless inheritance? && project.is_a?(::Project)

        ItemConsumerAuthorizationSubject.new(self, project)
      end

      def pinned_version
        @pinned_version ||= item.resolve_version(pinned_version_prefix)
      end

      def active_service_account
        service_account || parent_item_consumer&.service_account
      end

      def active_service_account_id
        service_account_id || parent_item_consumer&.service_account_id
      end

      # The role the flow's shared account holds in the given project. An
      # autonomous trigger's dedicated account matches it, so nil (no account,
      # or one that is not a member) means there is no role to match.
      def active_service_account_access_level(project)
        account = active_service_account
        return unless account

        project.team.max_member_access(account.id).nonzero?
      end

      class << self
        def service_account_needed_for_project?(service_account, project_id)
          return false if service_account.nil? || project_id.nil?

          # A parent outside the project's current top-level group no longer grants access,
          # for example after the project was transferred out of that group.
          parent_item_consumers = for_service_account(service_account)
            .for_groups(::Project.root_namespace_id_subquery(project_id))

          return true if exists?(parent_item_consumer: parent_item_consumers, project_id: project_id)

          inherited_for_service_account_and_project_id?(service_account, project_id)
        end

        def query_with_synthesized_foundational_agents(for_container, item_consumer_attributes)
          foundational_agent_ids = enabled_foundational_agent_ids(for_container)
          return all if foundational_agent_ids.empty?

          foundational_consumers = foundational_consumers(foundational_agent_ids, item_consumer_attributes)

          foundational_agents_union_query(foundational_consumers)
        end

        private

        # Inheritance records live only on top-level groups and create no per-project records,
        # so match on the project's root group. Not feature-flagged: this guards membership deletion.
        def inherited_for_service_account_and_project_id?(service_account, project_id)
          inheritance
            .for_service_account(service_account)
            .for_groups(::Project.root_namespace_id_subquery(project_id))
            .exists?
        end

        def enabled_foundational_agent_ids(container)
          return [] if container.nil?

          ids = container.root_ancestor.enabled_foundational_agents.map(&:global_catalog_id)
          Ai::Catalog::Item.where(id: ids).limit(ids.count).pluck(:id)
        end

        def foundational_agents_union_query(foundational_consumers)
          foundational_agents_sql = foundational_agents_sql(foundational_consumers)
          foundational_agents_relation = unscoped.from("(#{foundational_agents_sql}) AS #{table_name}")

          from_union([all, foundational_agents_relation], remove_duplicates: false)
        end

        def foundational_consumers(foundational_agent_ids, item_consumer_attributes)
          foundational_agent_ids.each_with_index.map do |id, index|
            # We need an ID since GraphQL will remove duplicate items with the same ID (including nil)
            new(item_consumer_attributes.merge(ai_catalog_item_id: id, enabled: true, id: -(index + 1)))
          end
        end

        def foundational_agents_sql(foundational_consumers)
          foundational_agents_values = foundational_consumers.map do |consumer|
            # Enums need their raw integer, not the cast string, but read_attribute_before_type_cast
            # only returns that for an unset (default) enum, so map explicitly-set ones by hand.
            values = column_names.map do |c|
              enum_values = defined_enums[c]
              raw_value = enum_values ? enum_values[consumer[c]] : consumer.read_attribute_before_type_cast(c)

              connection.quote(raw_value)
            end
            values_with_cast = values.zip(column_names).map do |value, column|
              type = columns_hash[column.to_s].type

              "#{value}::#{type}"
            end

            "(#{values_with_cast.join(', ')})"
          end

          <<~SQL
            SELECT * FROM (VALUES #{foundational_agents_values.join(', ')})
            AS ai_catalog_item_consumers(#{column_names.join(', ')})
          SQL
        end
      end

      private

      def sharding_keys
        [:group, :project]
      end

      def organization_id_from_sharding_key
        group&.organization_id || project&.organization_id
      end

      def validate_organization_match
        return if ai_catalog_item_id.nil? || item.organization_id == organization_id_from_sharding_key

        errors.add(:item, s_("AICatalog|must be enabled in the same organization"))
      end

      def validate_item_privacy_allowed
        return if item.visibility_public? || item.project.nil?
        return if project && item.project == project
        return if group && item.project.root_group == group
        return if restricted_item_within_same_hierarchy?

        message = if item.visibility_private?
                    s_('AICatalog|is private in another project')
                  else
                    s_("AICatalog|is restricted and cannot be used outside the owning project's top-level group")
                  end

        errors.add(:item, message)
      end

      def restricted_item_within_same_hierarchy?
        return false unless item.project && item.visibility_restricted?

        root_ancestor == item.project.root_ancestor
      end

      def validate_item_allowed_by_namespace_restriction
        return if item.nil? || container.nil?
        return unless item.blocked_by_namespace_restriction?(root_ancestor)

        errors.add(:item,
          s_('AICatalog|cannot be enabled because your top-level group settings block enabling ' \
            'items outside of its hierarchy'))
      end

      def validate_service_account
        if group.nil? || !group.root?
          errors.add(:service_account,
            s_('AICatalog|can only be set when enabling an agent or flow for a top-level group'))
          return
        end

        errors.add(:service_account, s_('AICatalog|must be a service account')) unless service_account.service_account?

        return unless service_account.provisioned_by_group_id != group_id

        errors.add(:service_account, s_('AICatalog|must be the same service account as the top-level group'))
      end

      def validate_parent_item_consumer
        if project.nil?
          errors.add(:parent_item_consumer,
            s_('AICatalog|can only be set when enabling an agent or flow for a project'))
          return
        end

        unless parent_item_consumer.group == project.root_ancestor
          errors.add(:parent_item_consumer, s_("AICatalog|must belong to this project's top-level group"))
          return
        end

        return if parent_item_consumer.ai_catalog_item_id == ai_catalog_item_id

        errors.add(:parent_item_consumer, s_("AICatalog|must be for the same item"))
      end

      def validate_item_uniqueness
        scope_field = %i[group_id project_id].find { |field| self[field].present? }
        return unless scope_field

        scope = self.class.where(item: item, scope_field => self[scope_field])
        scope = scope.where.not(id: id) if persisted?

        errors.add(:base, _('Agent or flow already enabled')) if scope.exists?
      end

      def validate_kind_unchanged
        return unless kind_changed?

        errors.add(:kind, s_('AICatalog|cannot be changed'))
      end

      def validate_inheritance_requires_top_level_group
        return if group.present? && group.root?

        errors.add(:base, s_('AICatalog|Inheritance is only supported for a top-level group'))
      end

      def validate_inheritance_item_visibility
        return if item.nil? || !item.visibility_private?

        errors.add(:item, s_('AICatalog|cannot be inherited because it is private'))
      end

      def service_account_required?
        project.nil? && group&.root? && (item&.flow? || item&.third_party_flow?)
      end
    end
  end
end

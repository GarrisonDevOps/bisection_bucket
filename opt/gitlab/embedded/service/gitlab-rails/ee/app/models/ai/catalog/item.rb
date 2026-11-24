# frozen_string_literal: true

module Ai
  module Catalog
    class Item < ApplicationRecord
      include FromUnion
      include Gitlab::SQL::Pattern

      FOUNDATIONAL_FLOWS_LIMIT = 100
      FOUNDATIONAL_EXTERNAL_AGENT_IDS = [2337, 2334, 2331, 2332].freeze
      SKILL_NAME_FORMAT = /\A[a-z0-9]+(?:-[a-z0-9]+)*\z/
      VERSIONS_LIMIT = 1000

      MINIMUM_ROLE_READ_PRIVATE_ITEMS = Gitlab::Access::GUEST

      self.table_name = "ai_catalog_items"

      validates :organization, :latest_version, :item_type, :description, :name, :verification_level, presence: true

      validates :name, length: { minimum: 3, maximum: 255 }, allow_nil: true, unless: :skill?

      # A skill's name is its directory name, so it follows the Agent Skills specification rather
      # than the general bounds, which would refuse a specification-valid skill on save.
      # https://agentskills.io/specification
      validates :name, length: { minimum: 1, maximum: 64 }, allow_nil: true, if: :skill?
      validates :name, format: {
        with: SKILL_NAME_FORMAT,
        message: ->(*) { s_('AICatalog|may only contain lowercase letters, numbers, and single hyphens') }
      }, allow_nil: true, if: :skill?
      validates :project, presence: true, if: :skill?
      validate :skill_name_must_match_directory, if: :skill?

      validates :description, length: { maximum: 1_024 }, allow_nil: true

      validate :validate_visibility_cannot_be_reduced
      validate :validate_foundational_item_must_be_public

      belongs_to :organization, class_name: 'Organizations::Organization', optional: false
      belongs_to :project
      belongs_to :latest_version, class_name: 'Ai::Catalog::ItemVersion', optional: false, autosave: true
      belongs_to :latest_released_version, class_name: 'Ai::Catalog::ItemVersion', optional: true

      validate :organization_match

      validate :item_type_must_not_be_foundational
      validate :versions_limit_not_reached, if: :new_version_for_existing_item?

      has_many :versions, class_name: 'Ai::Catalog::ItemVersion', foreign_key: :ai_catalog_item_id, inverse_of: :item
      has_many :consumers, class_name: 'Ai::Catalog::ItemConsumer', foreign_key: :ai_catalog_item_id, inverse_of: :item
      has_many :stars, class_name: 'Ai::Catalog::ItemStar', foreign_key: :ai_catalog_item_id, inverse_of: :item

      has_many(
        :dependents,
        foreign_key: :dependency_id, inverse_of: :dependency, class_name: 'Ai::Catalog::ItemVersionDependency'
      )

      enum :verification_level, ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS

      scope :for_verification_level, ->(level) { where(verification_level: level) }
      scope :in_organization, ->(organization) { where(organization: organization) }
      scope :for_project, ->(project) { where(project: project) }
      scope :not_deleted, -> { where(deleted_at: nil) }
      scope :public_only, -> { where(visibility: :public) }
      scope :without_restricted, -> { where.not(visibility: :restricted) }
      scope :restricted_only, -> { where(visibility: :restricted) }
      scope :restricted_within_group_hierarchy, ->(container) {
        restricted_only.within_group_hierarchy_or_foundational(container.root_ancestor)
      }

      scope :within_group_hierarchy_or_foundational, ->(top_level_group) {
        unless top_level_group.is_a?(::Group) && top_level_group.root?
          raise ArgumentError, 'top_level_group must be a root group'
        end

        where(project: top_level_group.all_projects).or(where(foundational_arel_predicate))
      }
      scope :search, ->(query) { fuzzy_search(query, [:name, :description]) }
      scope :with_ids, ->(ids) { where(id: ids) }
      scope :with_item_type, ->(item_type) { where(item_type: item_type) }
      scope :preload_latest_version, -> { includes(:latest_version) }

      scope :without_consumers, -> { left_joins(:consumers).where(ai_catalog_item_consumers: { id: nil }) }

      scope :order_by_last_30_day_usage_count_desc, -> { reorder(last_30_day_usage_count: :desc, id: :desc) }
      scope :order_by_last_30_day_usage_count_asc, -> { reorder(last_30_day_usage_count: :asc, id: :asc) }

      scope :order_by_star_count_desc, -> { reorder(star_count: :desc, id: :desc) }
      scope :order_by_star_count_asc, -> { reorder(star_count: :asc, id: :asc) }

      scope :order_by_id_asc, -> { order(id: :asc) }

      SORT_SCOPES = {
        usage_count_desc: :order_by_last_30_day_usage_count_desc,
        usage_count_asc: :order_by_last_30_day_usage_count_asc,
        star_count_desc: :order_by_star_count_desc,
        star_count_asc: :order_by_star_count_asc
      }.freeze

      scope :sort_by_key, ->(key) {
        scope_name = SORT_SCOPES[key]
        # rubocop:disable GitlabSecurity/PublicSend -- key is allowlisted by SORT_SCOPES hash
        scope_name ? public_send(scope_name) : all
        # rubocop:enable GitlabSecurity/PublicSend
      }

      scope :foundational_flows, -> { where.not(foundational_flow_reference: nil) }
      scope :with_foundational_flow_reference, ->(reference) { where(foundational_flow_reference: reference) }
      scope :include_foundational_items, ->(organization_id) {
        columns = Ai::Catalog::Item.columns.to_h { |column| [column.name.to_sym, column.sql_type] }

        foundational_agents_sql = Ai::FoundationalChatAgent.to_sql(
          columns_with_types: columns.merge(reference: :text),
          column_overrides: { organization_id: organization_id, id: nil }
        )

        foundational_items_relation = unscoped.from("(#{foundational_agents_sql}) AS #{table_name}")

        custom_items = unscoped.select(*columns.keys, 'NULL AS reference')

        foundational_items_relation = foundational_items_relation.select(*columns.keys, :reference)

        # Explicit select keeps the union-only `reference` value if a column is ignored later,
        # since `ignore_column` makes the default SELECT enumerate table columns
        union = from_union([custom_items, foundational_items_relation], remove_duplicates: false)
          .select(*columns.keys, :reference)
        return union unless foundational_chat_agent_ids.present?

        union.where("(id NOT IN (?) OR id IS NULL)", foundational_chat_agent_ids)
      }

      before_destroy :prevent_deletion_if_consumers_exist

      AGENT_TYPE = :agent
      FLOW_TYPE = :flow
      THIRD_PARTY_FLOW_TYPE = :third_party_flow
      FOUNDATIONAL_AGENT_TYPE = :foundational_agent
      SKILL_TYPE = :skill

      enum :item_type, {
        AGENT_TYPE => 1,
        FLOW_TYPE => 2,
        THIRD_PARTY_FLOW_TYPE => 3,
        FOUNDATIONAL_AGENT_TYPE => 4,
        SKILL_TYPE => 5
      }

      enum :visibility, { private: 0, restricted: 1, public: 2 }, prefix: :visibility

      # Most restrictive first. The enum integers are persisted and cannot be
      # reordered, so comparisons rank visibilities here instead.
      VISIBILITY_ORDER = %w[private restricted public].freeze

      class << self
        def visibility_rank(visibility)
          VISIBILITY_ORDER.index(visibility.to_s) ||
            raise(ArgumentError, "Unranked visibility: #{visibility}")
        end

        def public_or_visible_to_user(current_user, allow_restricted: false)
          # Anonymous users always see public items only, regardless of allow_restricted
          return public_only if current_user.nil?

          pa_table = ProjectAuthorization.arel_table
          member_condition = pa_table
            .project(1)
            .where(pa_table[:project_id].eq(arel_table[:project_id]))
            .where(pa_table[:user_id].eq(current_user.id))
            .where(pa_table[:access_level].gteq(MINIMUM_ROLE_READ_PRIVATE_ITEMS))
          member_condition = exclude_banned_root_namespaces(member_condition, current_user)

          public_condition = arel_table[:visibility].eq(visibilities[:public])
          member_exists = member_condition.exists
          visibility_filter = public_condition.or(member_exists)

          result = where(visibility_filter)
          result = result.without_restricted unless allow_restricted
          result
        end

        def visible_to_user_with_priority_ordering(current_user, allow_restricted: false)
          # Anonymous users never see restricted items, regardless of allow_restricted
          allow_restricted = false if current_user.nil?

          inner_query = build_inner_query_with_access_level(current_user)
          outer_relation = apply_visibility_filter(inner_query, allow_restricted: allow_restricted)
          apply_catalog_priority_ordering(outer_relation)
        end

        def foundational_flow_ids
          foundational_flows.order(:id).limit(FOUNDATIONAL_FLOWS_LIMIT).pluck_primary_key
        end

        # Returns the global_catalog_ids of foundational chat agents.
        # These IDs are hardcoded in Ai::FoundationalChatAgentsDefinitions and only apply to SaaS.
        # On non-SaaS environments, these IDs would point to different items, so we return
        # an empty array to avoid any problem.
        def foundational_chat_agent_ids
          return [] unless ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only)

          ::Ai::FoundationalChatAgent.all.filter_map(&:global_catalog_id)
        end

        # Returns the IDs of External agents.
        # These IDs are hardcoded in Ai::Catalog::Item::FOUNDATIONAL_EXTERNAL_AGENT_IDS and only apply to SaaS.
        # On non-SaaS environments, these IDs would point to different items, so we return
        # an empty array to avoid any problem.
        def foundational_external_agent_ids
          return [] unless Gitlab.com_except_jh? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Temporary solution until we remove the hardcoded foundational item IDs.Discussion https://gitlab.com/gitlab-org/gitlab/-/merge_requests/222430#note_3086367966

          FOUNDATIONAL_EXTERNAL_AGENT_IDS
        end

        def foundational_flow_ids_for_references(references)
          return {} if references.blank?

          foundational_flows
            .where(foundational_flow_reference: references)
            .limit(FOUNDATIONAL_FLOWS_LIMIT)
            .pluck(:foundational_flow_reference, :id)
            .to_h
        end

        # Arel predicate identifying database-bound foundational items
        def foundational_arel_predicate
          gitlab_maintained = ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained]
          predicate = arel_table[:verification_level].eq(gitlab_maintained)

          chat_agent_ids = foundational_chat_agent_ids
          predicate = predicate.or(arel_table[:id].in(chat_agent_ids)) if chat_agent_ids.present?

          external_agent_ids = foundational_external_agent_ids
          predicate = predicate.or(arel_table[:id].in(external_agent_ids)) if external_agent_ids.present?

          predicate
        end

        def build_inner_query_with_access_level(current_user)
          # Anonymous users have no memberships, so their access_level is always NULL
          return reselect(Arel.star, Arel.sql('NULL::integer AS access_level')) if current_user.nil?

          items_table = arel_table
          pa_table = ProjectAuthorization.arel_table

          access_level_subquery = pa_table
            .project(pa_table[:access_level])
            .where(pa_table[:user_id].eq(current_user.id))
            .where(pa_table[:project_id].eq(items_table[:project_id]))

          access_level_subquery = exclude_banned_root_namespaces(access_level_subquery, current_user)

          reselect(
            Arel.star,
            Arel::Nodes::As.new(access_level_subquery, Arel.sql('access_level'))
          )
        end

        def exclude_banned_root_namespaces(authorization_subquery, current_user)
          return authorization_subquery if current_user.can_admin_all_resources?

          banned_root_ids = current_user.namespace_bans.filter_map do |ban|
            ban.namespace_id if ban.namespace.unique_project_download_limit_enabled?
          end
          return authorization_subquery if banned_root_ids.empty?

          banned_project = Project.select(1)
            .joins(:project_namespace)
            .where(Project.arel_table[:id].eq(arel_table[:project_id]))
            .where('namespaces.traversal_ids[1] IN (?)', banned_root_ids)

          authorization_subquery.where(banned_project.arel.exists.not)
        end

        def apply_visibility_filter(inner_query, allow_restricted: false)
          items_table = Arel::Table.new('ai_catalog_items')
          access_level_attr = items_table[:access_level]
          visibility_attr = items_table[:visibility]

          base = unscoped.from("(#{inner_query.to_sql}) ai_catalog_items")
          access_condition = access_level_attr.gteq(MINIMUM_ROLE_READ_PRIVATE_ITEMS)

          result = base.where(access_condition.or(visibility_attr.in(visibilities.values_at('restricted', 'public'))))
          result = result.without_restricted unless allow_restricted
          result
        end

        def apply_catalog_priority_ordering(relation)
          priority_case = build_catalog_priority_case

          order_columns = [
            Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
              attribute_name: 'catalog_priority',
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

          relation_with_priority = relation.select(arel_table[Arel.star], priority_case.as('catalog_priority'))
          relation_with_priority.reorder(Gitlab::Pagination::Keyset::Order.build(order_columns))
        end

        # Builds a SQL CASE expression to determine catalog item display priority.
        #
        # Priority order:
        # 1. Foundational chat agents and external agents (SaaS only) - matched by hardcoded IDs
        # 2. Foundational flows and external agents (non-SaaS) - identified by verification_level
        #    set to gitlab_maintained (100). On non-SaaS, foundational chat agents are not stored
        #    in the catalog, so they are excluded. However, external agents are created with
        #    verification_level = gitlab_maintained, so they are prioritized through this condition.
        # 3. Items from the user's own projects - determined by access_level from project_authorizations
        # 4. All remaining public items
        def build_catalog_priority_case
          items_table = arel_table
          gitlab_maintained = Namespaces::VerifiedNamespace::VERIFICATION_LEVELS[:gitlab_maintained]
          access_level_expr = Arel.sql('access_level')

          priority = Arel::Nodes::Case.new

          chat_agent_ids = foundational_chat_agent_ids
          external_agent_ids = foundational_external_agent_ids

          priority = priority.when(items_table[:id].in(chat_agent_ids)).then(1) if chat_agent_ids.present?
          priority = priority.when(items_table[:id].in(external_agent_ids)).then(2) if external_agent_ids.present?

          priority
            .when(items_table[:verification_level].eq(gitlab_maintained)).then(3)
            .when(access_level_expr.not_eq(nil)).then(4)
            .else(5)
        end
      end

      def deleted?
        deleted_at.present?
      end

      def at_least_as_visible_as?(other_visibility)
        self.class.visibility_rank(visibility) >= self.class.visibility_rank(other_visibility)
      end

      def soft_delete
        update(deleted_at: Time.zone.now)
      end

      def star(user)
        stars.create!(user: user)
      rescue ActiveRecord::RecordNotUnique
        stars.find_by(user: user)
      end

      def unstar(user)
        star = stars.find_by(user: user)
        return false unless star

        star.destroy.destroyed?
      end

      def human_item_type
        return 'external agent' if third_party_flow?

        item_type
      end

      # Returns the latest released version of this item.
      # Uses a fallback until a data migration will allow us to use `latest_released_version` directly.
      # https://gitlab.com/gitlab-org/gitlab/-/issues/572145
      #
      # This fallback is safe because all older items without a `latest_released_version` were created
      # when `latest_version` always pointed to a released version.
      def latest_released_version_with_fallback
        latest_released_version || (latest_version if latest_version.released?)
      end

      def definition(pinned_version_prefix = nil, pinned_version_id = nil)
        version = pinned_version_id ? ItemVersion.find(pinned_version_id) : resolve_version(pinned_version_prefix)

        case item_type.to_sym
        when AGENT_TYPE
          AgentDefinition.new(self, version)
        when FLOW_TYPE
          raise ArgumentError, "pinned_version_id is not supported for flows" if pinned_version_id

          FlowDefinition.new(self, version)
        when THIRD_PARTY_FLOW_TYPE
          version.definition
        when SKILL_TYPE
          SkillDefinition.new(self, version)
        end
      end

      # Pass `track_missing: false` when the prefix is user input that the caller validates,
      # so an unknown version is not reported as an error.
      def resolve_version(pinned_version_prefix = nil, track_missing: true)
        return latest_version if pinned_version_prefix.nil?

        version = versions.find_by(version: pinned_version_prefix)

        if version.nil? && track_missing
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
            StandardError.new('Ai::Catalog::Item#resolve_version did not resolve a version'),
            item_id: id, pinned_version_prefix: pinned_version_prefix
          )
        end

        version
      end

      # TODO: replace versions query with latest_released_version after the data migration from
      # https://gitlab.com/gitlab-org/gitlab/-/issues/572145 has run.
      def next_version_number(bump_level: ItemVersion::VERSION_BUMP_MINOR)
        latest_released = versions.released.order_by_id_desc.take

        return BaseService::DEFAULT_VERSION unless latest_released

        latest_released.version_bump(bump_level)
      end

      def lock_without_reload!
        self.class.lock.find(id)
      end

      def build_new_version(version_params)
        versions.build(version_params).tap do |new_version|
          self.latest_version = new_version
        end
      end

      def foundational?
        foundational_third_party_flow? || foundational_chat_agent? || foundational_flow? ||
          foundational_agent?
      end

      def blocked_by_namespace_restriction?(container)
        return false if foundational?

        root_ancestor = container.root_ancestor
        return false unless root_ancestor.ai_catalog_restricted_to_group_hierarchy

        project.present? && project.root_ancestor != root_ancestor
      end

      def outside_restricted_hierarchy?(container)
        return false unless visibility_restricted? && project.present?

        project.root_ancestor != container.root_ancestor
      end

      def foundational_chat_agent?
        agent? && id.present? &&
          ::Gitlab::Saas.feature_available?(:gitlab_duo_saas_only) &&
          !!::Ai::FoundationalChatAgent.find_by(global_catalog_id: id)
      end

      def foundational_flow?
        flow? && foundational_flow_reference.present?
      end

      def foundational_third_party_flow?
        third_party_flow? && gitlab_maintained?
      end

      def custom_flow?
        flow? && !foundational_flow?
      end

      def custom_agent?
        agent? && !foundational_chat_agent?
      end

      def custom_agent_disabled_for?(root_ancestor)
        custom_agent? && !root_ancestor.duo_custom_agents_enabled
      end

      def custom_third_party_flow?
        third_party_flow? && !foundational_third_party_flow?
      end

      def foundational_flow
        return unless foundational_flow?

        ::Ai::Catalog::FoundationalFlow[foundational_flow_reference]
      end

      # Only a flow carries a trigger, and a foundational flow whose goal still holds
      # resource identity refuses one. Opting one in also means relaxing its goal
      # validator. https://gitlab.com/gitlab-org/gitlab/-/work_items/608242
      def accepts_trigger_goal?
        return false unless flow? || third_party_flow?

        flow = foundational_flow

        flow.nil? || flow.accepts_trigger_goal
      end

      def schedulable?
        return false unless flow?
        return true unless foundational_flow?

        !!foundational_flow&.schedulable
      end

      def foundational_agent_reference
        return unless foundational_chat_agent?

        ::Ai::FoundationalChatAgent.find_by(global_catalog_id: id)&.reference
      end

      def enabled_in_managed_by_project?
        return false unless project_id

        consumers.where(project_id: project_id, enabled: true).exists?
      end

      # Checks the children of the group's direct configuration, which are what replacing it with
      # inheritance deletes (through the cascading foreign key on parent_item_consumer_id).
      def direct_project_configurations_in_group?(group)
        ItemConsumer.where(parent_item_consumer_id: consumers.for_groups(group).direct.select(:id)).exists?
      end

      def banzai_render_context(_field)
        { project: project, group: nil }
      end

      private

      def prevent_deletion_if_consumers_exist
        return unless consumers.any?

        errors.add(:base, 'Cannot delete an item that has consumers')
        throw :abort # rubocop:disable Cop/BanCatchThrow -- We handle soft deleting in `ee/app/services/ai/catalog/agents/destroy_service.rb`
      end

      def organization_match
        return if project_id.nil? || project.organization_id == organization_id

        errors.add(:project, _("organization must match the agent or flow's organization"))
      end

      def new_version_for_existing_item?
        persisted? && latest_version&.new_record?
      end

      def versions_limit_not_reached
        return if versions.limit(VERSIONS_LIMIT).count < VERSIONS_LIMIT

        errors.add(:base, format(
          s_('AICatalog|This item has reached the maximum of %{limit} versions. ' \
            'To make more changes, create a new item.'),
          limit: VERSIONS_LIMIT
        ))
      end

      def item_type_must_not_be_foundational
        return unless foundational_agent?

        errors.add(:item_type, 'Cannot store foundational item types in database')
      end

      def validate_visibility_cannot_be_reduced
        return unless visibility_changed? && reducing_visibility?

        if visibility_restricted?
          return unless has_consumers_outside_group_hierarchy?

          errors.add(:visibility,
            s_('AICatalog|can\'t be made restricted because this item is enabled outside the top-level group hierarchy')
          )
        elsif visibility_private?
          return unless has_external_consumers?

          errors.add(:visibility,
            s_('AICatalog|can\'t be made private because this item is enabled outside its owning project')
          )
        end
      end

      def reducing_visibility?
        self.class.visibility_rank(visibility) < self.class.visibility_rank(visibility_was)
      end

      def skill_name_must_match_directory
        path = latest_version&.def_path
        return if name.blank? || !path.is_a?(String)
        return if name == File.basename(File.dirname(path))

        errors.add(:name, s_('AICatalog|must match the skill directory name'))
      end

      def validate_foundational_item_must_be_public
        return unless foundational?
        return if visibility_public?

        errors.add(:visibility, s_('AICatalog|foundational items must be public'))
      end

      def has_external_consumers?
        return false unless project_id.present?

        external = consumers.not_for_projects(project_id)
        root = project.root_ancestor
        external = external.where.not(id: consumers.direct.for_groups(root).select(:id)) if root.is_a?(::Group)
        external.exists?
      end

      def has_consumers_outside_group_hierarchy?
        return false unless project_id.present?

        root_group = project.root_ancestor
        return has_external_consumers? unless root_group.is_a?(::Group)

        consumers.any_outside_group_hierarchy?(root_group)
      end
    end
  end
end

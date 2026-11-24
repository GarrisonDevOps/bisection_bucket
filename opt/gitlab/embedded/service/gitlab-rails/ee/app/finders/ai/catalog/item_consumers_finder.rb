# frozen_string_literal: true

module Ai
  module Catalog
    # Pass `include_inherited: false` to exclude consumers that a project inherits from
    # its top-level group. They're included by default when `project_id` is given.
    class ItemConsumersFinder
      include Gitlab::Utils::StrongMemoize

      USAGE_SORT_DIRECTIONS = {
        usage_count_asc: :asc,
        usage_count_desc: :desc
      }.freeze

      def initialize(current_user, params: {})
        @current_user = current_user
        @params = params
      end

      def execute
        validate_args!

        consumers = by_container
        consumers = include_foundational_consumers(consumers) if include_foundational_consumers?
        consumers = by_group_hierarchy_restriction(consumers) if restrict_to_group_hierarchy?
        consumers = by_item(consumers) if item_id
        consumers = by_foundational_flow_reference(consumers) if foundational_flow_reference
        consumers = by_configurable_for_project(consumers) if configurable_for_project_id
        consumers = by_item_type(consumers)
        consumers = exclude_disabled_item_types(consumers) if container

        if usage_sort_direction
          consumers.with_usage_ordering(usage_sort_direction)
        else
          consumers.with_priority_ordering(current_user)
        end
      end

      def container
        @container ||= project_id ? Project.find_by_id(project_id) : Group.find_by_id(group_id)
      end

      private

      attr_reader :current_user, :params

      def usage_sort_direction
        USAGE_SORT_DIRECTIONS[params[:sort]]
      end
      strong_memoize_attr :usage_sort_direction

      def include_foundational_consumers?
        params.fetch(:include_foundational_consumers, false)
      end

      def include_foundational_consumers(consumers)
        return consumers unless filtered_item_types.include?(Ai::Catalog::Item::AGENT_TYPE)
        return consumers unless Gitlab.com_except_jh? # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- Temporary, until we stop storing foundational agents in the database https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221730#note_3086960423

        consumers.with_synthesized_foundational_agent_consumers(container, params.slice(:project_id, :group_id))
      end

      def validate_args!
        case params.values_at(:project_id, :group_id).compact.count
        when 0
          raise ArgumentError, 'Must provide either project_id or group_id param'
        when 2
          params.delete(:group_id)
        end
      end

      def project_id
        params[:project_id]
      end

      def group_id
        params[:group_id]
      end

      def item_id
        params[:item_id]
      end

      def configurable_for_project_id
        params[:configurable_for_project_id]
      end

      def item_types
        [params[:item_type], *params[:item_types]].compact
      end

      def foundational_flow_reference
        params[:foundational_flow_reference]
      end

      def by_item(consumers)
        consumers.for_item(item_id)
      end

      def by_item_type(consumers)
        return consumers if filtered_item_types == all_types

        consumers.with_item_type(filtered_item_types)
      end

      def by_foundational_flow_reference(consumers)
        matching_item_ids = ::Ai::Catalog::Item
                              .with_foundational_flow_reference(foundational_flow_reference)
                              .select(:id)
        consumers.for_item(matching_item_ids)
      end

      def by_group_hierarchy_restriction(consumers)
        allowed_items = ::Ai::Catalog::Item.within_group_hierarchy_or_foundational(container.root_ancestor)
        consumers.for_item(allowed_items.select(:id))
      end

      def none
        ItemConsumer.none
      end

      def by_container
        return none if container.nil?
        return none unless Ability.allowed?(current_user, :read_ai_catalog_item_consumer, container)

        consumers = container.configured_ai_catalog_items
        return consumers unless include_inherited?

        consumers.or(ItemConsumer.for_groups(container.root_ancestor).inheritance)
      end

      def include_inherited?
        return false unless container.is_a?(::Project)

        root_ancestor = container.root_ancestor
        return false unless root_ancestor.is_a?(::Group)
        return false unless ::Feature.enabled?(:ai_catalog_group_inherited_consumers, root_ancestor)

        params[:include_inherited] != false
      end
      strong_memoize_attr :include_inherited?

      strong_memoize_attr def filtered_item_types
        types = (item_types.presence || all_types).map(&:to_sym)

        # (Foundational flows)
        if foundational_flow_reference.present?
          return [] unless Ability.allowed?(current_user, :read_ai_foundational_flow, container)
          return [] if beta_foundational_flow_without_beta_features?

          return [Ai::Catalog::Item::FLOW_TYPE]
        end

        # (Custom flows / foundational flows)
        # FLOW_TYPE covers both custom flows and foundational flows (distinguished by foundational_flow_reference).
        # Remove FLOW_TYPE only when both custom and foundational flow access are denied.
        if foundational_flow_reference.blank? &&
            !Ability.allowed?(current_user, :read_ai_catalog_flow, container) &&
            !Ability.allowed?(current_user, :read_ai_foundational_flow, container)
          types -= [Ai::Catalog::Item::FLOW_TYPE]
        end

        unless Ability.allowed?(current_user, :read_ai_catalog_third_party_flow, container)
          types -= [Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE]
        end

        types
      end

      def by_configurable_for_project(consumers)
        consumers.with_items_configurable_for_project(configurable_for_project_id)
      end

      def exclude_disabled_item_types(consumers)
        settings = container.root_ancestor.namespace_settings

        consumers = consumers.excluding_custom_agents unless settings&.duo_custom_agents_enabled
        consumers = consumers.excluding_custom_flows unless settings&.duo_custom_flows_enabled
        consumers = consumers.excluding_external_agents unless settings&.duo_external_agents_enabled
        consumers
      end

      def all_types
        Ai::Catalog::Item.item_types.keys.map(&:to_sym)
      end

      def beta_foundational_flow_without_beta_features?
        return false unless foundational_flow_reference.present?
        return false unless ::Ai::Catalog::FoundationalFlow.beta?(foundational_flow_reference)

        if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
          !container.root_ancestor.experiment_features_enabled
        else
          !::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
        end
      end

      def restrict_to_group_hierarchy?
        container && container.root_ancestor.ai_catalog_restricted_to_group_hierarchy == true
      end
    end
  end
end

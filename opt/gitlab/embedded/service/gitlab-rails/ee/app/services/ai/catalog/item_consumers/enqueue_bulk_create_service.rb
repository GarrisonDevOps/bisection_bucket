# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class EnqueueBulkCreateService
        include Gitlab::Utils::StrongMemoize

        def initialize(
          current_user:, item:, project_ids:, trigger_types: nil, trigger_filter: nil,
          trigger_goals: nil, pinned_version: nil)
          @current_user = current_user
          @item = item
          @project_ids = GitlabSchema.parse_gids(project_ids, expected_type: ::Project).map(&:model_id).uniq
          @trigger_types = trigger_types
          @trigger_filter = trigger_filter
          @trigger_goals = trigger_goals
          @pinned_version = pinned_version
        end

        def execute
          return error(foundational_item_message) if item.foundational? && !item.third_party_flow?
          return error(trigger_types_required_message) if should_have_trigger_types? && trigger_types.blank?

          unsupported_argument = unsupported_trigger_argument_message
          return error(unsupported_argument) if unsupported_argument

          return error(version_not_released_message) if requested_version_invalid?
          return error(projects_not_available_message) unless all_projects_exist_and_authorized?
          return error(organization_mismatch_message) unless all_projects_in_item_organization?

          Gitlab::ApplicationContext.with_context(organization: item.organization) do
            BulkCreateWorker.perform_async(
              current_user.id,
              item.id,
              projects.map(&:id),
              worker_params
            )
          end

          ServiceResponse.success
        end

        private

        attr_reader :current_user, :item, :project_ids, :trigger_types, :trigger_filter, :trigger_goals,
          :pinned_version

        def worker_params
          { 'trigger_types' => trigger_types, 'trigger_filter' => trigger_filter,
            'trigger_goals' => trigger_goals, 'pinned_version' => pinned_version }.compact
        end

        strong_memoize_attr def projects
          Project.id_in(project_ids).with_project_setting
        end

        def should_have_trigger_types?
          item.flow? || item.third_party_flow?
        end

        # An item that carries no trigger of its own can use no trigger argument.
        def unsupported_trigger_argument_message
          return if should_have_trigger_types?

          return trigger_types_not_supported_message if trigger_types.present?
          return trigger_filter_not_supported_message if trigger_filter.present?

          trigger_goals_not_supported_message if trigger_goals.present?
        end

        def requested_version_invalid?
          pinned_version.present? && !item.resolve_version(pinned_version, track_missing: false)&.released?
        end

        def all_projects_exist_and_authorized?
          return false unless projects.size == project_ids.size

          ::Preloaders::ProjectPolicyPreloader.new(projects, current_user).execute

          DeclarativePolicy.user_scope do
            projects.all? { |project| allowed_for_project?(project) }
          end
        end

        def all_projects_in_item_organization?
          projects.all? { |project| project.organization_id == item.organization_id }
        end

        def allowed_for_project?(project)
          if item.agent?
            Ability.allowed?(current_user, :create_ai_catalog_agent_item_consumer, project)
          elsif item.flow?
            Ability.allowed?(current_user, :create_ai_catalog_flow_item_consumer, project)
          elsif item.third_party_flow?
            Ability.allowed?(current_user, :create_ai_catalog_third_party_flow_item_consumer, project)
          elsif item.skill?
            Ability.allowed?(current_user, :create_ai_catalog_skill_item_consumer, project)
          else
            raise ArgumentError, "Unsupported item type: #{item.item_type}"
          end
        end

        def error(message)
          ServiceResponse.error(message:)
        end

        def foundational_item_message
          s_('AICatalog|Foundational agents and flows must be enabled in the Admin area or group settings.')
        end

        def trigger_types_required_message
          s_('AICatalog|Trigger types are required for flows.')
        end

        def trigger_types_not_supported_message
          s_('AICatalog|Trigger types are not supported for this item type.')
        end

        def trigger_filter_not_supported_message
          s_('AICatalog|Trigger filters are not supported for this item type.')
        end

        def trigger_goals_not_supported_message
          s_('AICatalog|Trigger goals are not supported for this item type.')
        end

        def version_not_released_message
          s_('AICatalog|Pinned version must resolve to a released version of the agent or flow.')
        end

        def projects_not_available_message
          s_('AICatalog|One or more projects not found, or you do not have permission to ' \
            'enable this item in the project.')
        end

        def organization_mismatch_message
          s_('AICatalog|All projects must belong to the same organization as the agent or flow.')
        end
      end
    end
  end
end

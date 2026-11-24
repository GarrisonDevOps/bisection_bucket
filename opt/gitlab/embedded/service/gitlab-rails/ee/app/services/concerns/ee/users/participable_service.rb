# frozen_string_literal: true

module EE
  module Users
    module ParticipableService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      override :user_as_hash
      def user_as_hash(user)
        super.merge(user_disabled_fields(user))
      end

      override :org_user_detail_as_hash
      def org_user_detail_as_hash(detail)
        super.merge(user_disabled_fields(detail.user))
      end

      def user_disabled_fields(user)
        result = agent_status_check.execute(user)

        {
          disabled: result.disabled?,
          disabled_reason: result.disabled_reason,
          flow_trigger_events: lazy_user_flow_trigger_events(user).itself
        }
      end

      private

      def agent_status_check
        @agent_status_check ||= ::Ai::Agents::CheckAgentStatusService.new(current_user)
      end

      def lazy_user_flow_trigger_events(user)
        BatchLoader.for(user.id).batch(default_value: []) do |user_ids, loader|
          user_ids.each_slice(100) do |sliced_user_ids|
            triggers = ::Ai::FlowTrigger
              .applicable_to_container(
                participation_object,
                by_service_accounts: sliced_user_ids,
                project_ids: participation_object_project_ids
              )
              .include_parent_item_consumer

            triggers.group_by(&:service_account_id).each do |service_account_id, user_triggers|
              event_types = user_triggers.flat_map(&:event_types).uniq.compact.map do |event_type_id|
                ::Ai::FlowTrigger.event_type_from_id(event_type_id).upcase
              end

              loader.call(service_account_id, event_types)
            end
          end
        end
      end

      def participation_object_project_ids
        participation_object.project_ids if participation_object.is_a?(::Namespace)
      end
      strong_memoize_attr :participation_object_project_ids

      def preload_associations(users, &block)
        super do |user|
          lazy_user_flow_trigger_events(user)
        end
      end
    end
  end
end

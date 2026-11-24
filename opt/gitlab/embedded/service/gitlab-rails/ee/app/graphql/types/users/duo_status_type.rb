# frozen_string_literal: true

module Types
  module Users
    class DuoStatusType < BaseObject
      graphql_name 'UserDuoStatus'
      description 'Represents the Duo status for a user.'

      authorize :read_user
      authorize_granular_token parent_authorizes: :read_user

      field :disabled, GraphQL::Types::Boolean, null: false,
        description: 'Indicates if the user is disabled for assignment in Duo features.'
      field :disabled_reason, GraphQL::Types::String, null: true,
        description: 'Reason why the user is disabled for assignment in Duo features.'
      field :flow_trigger_events, [Types::Ai::FlowTrigger::EventTypeEnum], null: false,
        description: 'List of available flow trigger events for the user in Duo features.'

      def self.flow_trigger_events_by_user(parent_entity, user_ids)
        triggers = case parent_entity
                   when ::Project, ::Namespace
                     ::Ai::FlowTrigger.applicable_to_container(parent_entity, by_service_accounts: user_ids)
                   else
                     ::Ai::FlowTrigger.active.by_service_accounts(user_ids)
                   end

        triggers_by_user = triggers.include_parent_item_consumer.group_by(&:service_account_id)

        triggers_by_user.transform_values { |user_triggers| user_triggers.flat_map(&:event_types).uniq }
      end

      def flow_trigger_events
        BatchLoader::GraphQL.for(object.id).batch(default_value: [], key: parent_entity) do |user_ids, loader, batch|
          self.class.flow_trigger_events_by_user(batch[:key], user_ids).each do |user_id, event_types|
            loader.call(user_id, event_types)
          end
        end
      end

      def disabled
        agent_status_check_result.disabled?
      end

      def disabled_reason
        agent_status_check_result.disabled_reason
      end

      private

      def agent_status_check_result
        @agent_status_check_result ||= ::Ai::Agents::CheckAgentStatusService.new(current_user).execute(object)
      end

      def parent_entity
        @parent_entity ||= context[:duo_status_parent]
      end
    end
  end
end

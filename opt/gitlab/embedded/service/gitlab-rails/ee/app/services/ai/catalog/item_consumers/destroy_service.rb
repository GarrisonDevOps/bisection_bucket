# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      class DestroyService
        include EventsTracking

        def initialize(item_consumer, current_user)
          @current_user = current_user
          @item_consumer = item_consumer
        end

        def execute
          return error_no_permissions unless allowed?
          return error_foundational_flow_group_disable if foundational_flow_group_consumer?

          error_messages = nil

          flow_trigger_before_delete = item_consumer.flow_trigger

          ApplicationRecord.transaction do
            successfully_deleted, error_messages = remove_service_account_from_project
            raise ActiveRecord::Rollback unless successfully_deleted

            remove_service_account_from_all_projects

            successfully_deleted, error_messages = delete_item_consumer
            raise ActiveRecord::Rollback unless successfully_deleted
          end

          return error(error_messages) unless error_messages.nil?

          track_item_consumer_event(item_consumer, 'delete_ai_catalog_item_consumer', flow_trigger_before_delete)
          send_audit_events(item_consumer, audit_event_name)
          ServiceResponse.success(payload: { item_consumer: item_consumer })
        end

        private

        attr_reader :current_user, :item_consumer

        def audit_event_name
          "disable_ai_catalog_#{item_consumer.item.item_type}"
        end

        def allowed?
          Ability.allowed?(current_user, :admin_ai_catalog_item_consumer, item_consumer)
        end

        def foundational_flow_group_consumer?
          item_consumer.item.foundational_flow? && item_consumer.group.present?
        end

        def delete_item_consumer
          if item_consumer.destroy
            [true, nil]
          else
            [false, item_consumer.errors.full_messages]
          end
        end

        def remove_service_account_from_project
          service_account_id = item_consumer.parent_item_consumer&.service_account_id
          return [true, nil] if service_account_id.nil? || item_consumer.project.nil?

          member = item_consumer.project.team.find_member(service_account_id)

          return [true, nil] if member.nil?

          Members::DestroyService.new(member, current_user: current_user, skip_authorization: true).execute

          return [true, nil] if member.destroyed?

          errors = member.errors.full_messages.map { |err| "Service account membership: #{err}" }

          [false, errors]
        end

        def remove_service_account_from_all_projects
          return if item_consumer.service_account.nil? || item_consumer.group.nil?

          # Set user_id variable for the run_after_commit context
          user_id = current_user.id

          item_consumer.run_after_commit do
            Ai::Catalog::DeleteServiceAccountMembersFromHierarchyWorker.perform_async(
              user_id, service_account.id, group.id,
              { 'skip_authorization' => true }
            )
          end
        end

        def error_no_permissions
          error("You don't have permission to disable this agent or flow")
        end

        def error_foundational_flow_group_disable
          error(
            s_("AICatalog|Foundational flows can only be disabled for a group in the group's GitLab Duo settings")
          )
        end

        def error(message)
          ServiceResponse.error(message: Array(message))
        end
      end
    end
  end
end

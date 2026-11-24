# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      # Synchronizes a container's materialized foundational-flow consumers and triggers.
      #
      # Normal calls remain authorized by +current_user+. Project creation and post-import
      # repair may opt into the explicit inherited-project mode, where a validated root-group
      # consumer and project allowlist authorize only actor-role bypasses. Synchronization is
      # idempotent for sequential retries, removes stale consumers, records per-item failures,
      # and never elevates the initiating user's permissions.
      class SyncFoundationalFlowsService
        include ::Gitlab::Utils::StrongMemoize
        include ::Gitlab::Loggable

        INHERITED_PROJECT = :inherited_project

        def initialize(container, current_user: nil, provisioning_mode: nil, initiating_user_id: nil)
          @container = container
          @current_user = current_user
          @provisioning_mode = provisioning_mode
          @initiating_user_id = initiating_user_id || current_user&.id

          validate_provisioning_mode!
        end

        def execute
          unless foundational_flows_enabled?
            remove_all_flows
            return synchronization_response(successful_count: 0, failures: [])
          end

          sync_flows
        end

        private

        attr_reader :container, :current_user, :provisioning_mode, :initiating_user_id

        def foundational_flows_enabled?
          case container
          when Project
            container.project_setting&.duo_foundational_flows_enabled
          when Group, Namespace
            container.namespace_settings&.duo_foundational_flows_enabled
          else
            false
          end
        end

        def enabled_flow_catalog_item_ids
          container.enabled_flow_catalog_item_ids
        end

        def sync_flows
          target_ids = enabled_flow_catalog_item_ids
          items_by_id = Item.with_ids(target_ids).index_by(&:id)
          target_ids = target_ids.reject { |id| enablement_not_required?(items_by_id[id]) }
          failures = []

          unless inherited_project_provisioning? || provision_ai_catalog_allowed?
            failures = target_ids.map do |catalog_item_id|
              record_failure(catalog_item_id, items_by_id[catalog_item_id], :actor_not_allowed)
            end
            remove_consumers_not_in(target_ids)
            return synchronization_response(successful_count: 0, failures: failures)
          end

          target_ids.each do |catalog_item_id|
            item = items_by_id[catalog_item_id]
            unless item
              track_missing_item(catalog_item_id)
              failures << record_failure(catalog_item_id, nil, :catalog_item_missing)
              next
            end

            result = create_consumer_for_catalog_item(item)
            failures << record_failure(catalog_item_id, item, result.reason) if result.error?
          rescue StandardError => error
            raise unless inherited_project_provisioning?

            ::Gitlab::ErrorTracking.track_exception(
              error,
              catalog_item_id: catalog_item_id,
              container_id: container.id
            )
            failures << record_failure(catalog_item_id, item, :unexpected_error)
          end

          remove_consumers_not_in(target_ids)

          synchronization_response(successful_count: target_ids.size - failures.size, failures: failures)
        end

        def create_consumer_for_catalog_item(item)
          parent_consumer = find_parent_consumer_if_needed(item)
          inherited_authorization = inherited_project_authorization(item, parent_consumer)
          failure_reason = consumer_authorization_failure(parent_consumer, item)
          return synchronization_error(failure_reason) if failure_reason

          result = create_or_find_consumer(item, parent_consumer, inherited_authorization)
          consumer = extract_consumer_from_result(result, item)
          return synchronization_error(result.reason || :consumer_creation_failed) unless consumer

          trigger_result = create_trigger_if_needed(consumer, item, inherited_authorization)
          return synchronization_error(trigger_result.reason || :trigger_creation_failed) if trigger_result.error?

          ServiceResponse.success(payload: { item_consumer: consumer })
        end

        def find_parent_consumer_if_needed(item)
          return unless container.is_a?(Project)

          find_existing_consumer(item, container.root_ancestor)
        end

        def should_create_consumer?(parent_consumer)
          return true unless container.is_a?(Project)

          parent_consumer.present?
        end

        def authorized_to_create_consumer?(item)
          provision_ai_catalog_allowed? && Ability.allowed?(current_user, :read_ai_catalog_item, item)
        end

        def provision_ai_catalog_allowed?
          return false unless current_user

          Ability.allowed?(current_user, :provision_ai_catalog, container)
        end
        strong_memoize_attr :provision_ai_catalog_allowed?

        def create_or_find_consumer(item, parent_consumer, inherited_authorization)
          params = build_consumer_params(item, parent_consumer)
          service_arguments = {
            container: container,
            current_user: current_user,
            params: params
          }
          service_arguments[:authorization_context] = inherited_authorization if inherited_authorization

          ::Ai::Catalog::ItemConsumers::CreateService.new(**service_arguments).execute
        end

        def build_consumer_params(item, parent_consumer)
          params = { item: item, kind: :direct }
          params[:parent_item_consumer] = parent_consumer if parent_consumer
          params
        end

        def extract_consumer_from_result(result, item)
          return result.payload[:item_consumer] if result.success?
          return find_existing_consumer(item, container) if item_already_configured?(result)

          nil
        end

        def item_already_configured?(result)
          result.error? && result.reason == :already_configured
        end

        def find_existing_consumer(item, target_container)
          existing_consumers_by_item_id(target_container)[item.id]
        end

        def existing_consumers_by_item_id(target_container)
          @existing_consumers_cache ||= {}
          cache_key = [target_container.class.name, target_container.id]
          @existing_consumers_cache[cache_key] ||= target_container
            .configured_ai_catalog_items
            .direct
            .index_by(&:ai_catalog_item_id)
        end

        def create_trigger_if_needed(consumer, item, inherited_authorization)
          return ServiceResponse.success unless container.is_a?(Project)

          create_trigger_for_consumer(consumer, item, inherited_authorization)
        end

        def create_trigger_for_consumer(consumer, item, inherited_authorization)
          trigger_params = build_trigger_params(consumer, item)
          return ServiceResponse.success unless trigger_params.present?

          service_arguments = {
            project: container,
            current_user: current_user
          }
          service_arguments[:authorization_context] = inherited_authorization if inherited_authorization

          ::Ai::FlowTriggers::CreateService.new(**service_arguments).execute(trigger_params)
        end

        def build_trigger_params(consumer, item)
          return if consumer.active_service_account.nil?

          event_types = fetch_event_type_for_flow(item.foundational_flow_reference, consumer)
          return if event_types.empty?

          params = {
            description: format(InheritedProjectAuthorization::TRIGGER_DESCRIPTION, item.name),
            ai_catalog_item_consumer_id: consumer.id,
            event_types: event_types
          }

          default_filter = ::Ai::Catalog::FoundationalFlow[item.foundational_flow_reference]&.default_trigger_filter
          params[:filter] = default_filter if default_filter.present?

          params
        end

        # Such a flow runs in a Slack workspace's Duo group without a consumer. Until `slack_duo_group` is removed,
        # groups without the flag keep the consumer they had.
        def enablement_not_required?(item)
          return false unless item

          flow = ::Ai::Catalog::FoundationalFlow[item.foundational_flow_reference]
          return false unless flow&.requires_enablement == false

          ::Integrations::SlackWorkspace::Workspace.duo_group_feature_enabled?(container)
        end

        def remove_consumers_not_in(catalog_item_ids)
          ids_to_remove = foundational_flow_ids - catalog_item_ids

          container.remove_foundational_flow_consumers(ids_to_remove)
        end

        def remove_all_flows
          container.remove_foundational_flow_consumers(foundational_flow_ids)
        end

        def foundational_flow_ids
          Item.foundational_flow_ids
        end

        def fetch_event_type_for_flow(foundational_flow_reference, consumer)
          flow_definition = ::Ai::Catalog::FoundationalFlow[foundational_flow_reference]
          return [] unless flow_definition.present? && flow_definition.triggers.present?

          flow_definition.triggers.reject { |event| trigger_exists?(consumer, event) }
        end

        def trigger_exists?(consumer, event)
          event_type = ::Ai::FlowTrigger::EVENT_TYPES.key(event)
          return true unless event_type

          container.ai_flow_triggers.triggered_on(event_type).by_item_consumer_ids([consumer.id]).exists?
        end

        def track_missing_item(catalog_item_id)
          ::Gitlab::ErrorTracking.track_exception(
            ActiveRecord::RecordNotFound.new("Couldn't find Ai::Catalog::Item with id=#{catalog_item_id}"),
            catalog_item_id: catalog_item_id,
            container_id: container.id
          )
        end

        # Logs only stable identifiers and failure reasons, not downstream responses.
        def log_sync_failure(failure)
          payload = {
            Labkit::Fields::LOG_MESSAGE => 'Foundational flow was not synchronized',
            Labkit::Fields::GL_USER_ID => current_user&.id,
            catalog_item_id: failure[:catalog_item_id],
            foundational_flow_reference: failure[:foundational_flow_reference],
            failure_reason: failure[:reason].to_s
          }
          container_id_field = container.is_a?(Project) ? Labkit::Fields::GL_PROJECT_ID : Labkit::Fields::GL_NAMESPACE_ID
          payload[container_id_field] = container.id

          Gitlab::AppLogger.warn(build_structured_payload_labkit(**payload.compact))

          nil
        end

        def validate_provisioning_mode!
          unless provisioning_mode.nil? || inherited_project_provisioning?
            raise ArgumentError, "Unknown provisioning mode: #{provisioning_mode.inspect}"
          end

          if inherited_project_provisioning? && !container.is_a?(Project)
            raise ArgumentError, 'Inherited foundational-flow provisioning requires a project'
          end

          nil
        end

        def inherited_project_provisioning?
          provisioning_mode == INHERITED_PROJECT
        end

        def inherited_project_authorization(item, parent_consumer)
          return unless inherited_project_provisioning?

          InheritedProjectAuthorization.new(
            project: container,
            item: item,
            parent_consumer: parent_consumer,
            initiating_user: current_user,
            initiating_user_id: initiating_user_id
          )
        end

        # Inherited calls revalidate in the downstream typed authorization context.
        def consumer_authorization_failure(parent_consumer, item)
          return if inherited_project_provisioning?

          return :parent_consumer_missing unless should_create_consumer?(parent_consumer)
          return :actor_not_allowed unless authorized_to_create_consumer?(item)

          nil
        end

        def synchronization_error(reason)
          ServiceResponse.error(message: 'Foundational flow was not synchronized', reason: reason)
        end

        def record_failure(catalog_item_id, item, reason)
          failure = {
            catalog_item_id: catalog_item_id,
            foundational_flow_reference: item&.foundational_flow_reference,
            reason: reason
          }.compact

          log_sync_failure(failure)
          failure
        end

        def synchronization_response(successful_count:, failures:)
          ServiceResponse.success(payload: { successful_count: successful_count, failures: failures })
        end
      end
    end
  end
end

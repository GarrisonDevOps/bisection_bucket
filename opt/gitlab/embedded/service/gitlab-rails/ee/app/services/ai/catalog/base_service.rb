# frozen_string_literal: true

module Ai
  module Catalog
    class BaseService < ::BaseContainerService
      include Gitlab::InternalEventsTracking

      DEFAULT_VERSION = '1.0.0'

      # Untranslated on purpose: MCP tools match this against the serialized REST body, which is localized per request.
      INSUFFICIENT_PERMISSIONS_MESSAGE = 'You have insufficient permissions'

      def initialize(project:, current_user:, params: {})
        super(container: project, current_user: current_user, params: translate_public_to_visibility(params))
      end

      private

      def translate_public_to_visibility(params)
        return params if params[:visibility].present? || params[:public].nil?

        params.except(:public).merge(visibility: params[:public] ? :public : :private)
      end

      def allowed?
        Ability.allowed?(current_user, :admin_ai_catalog_item, project)
      end

      def error(message, payload: {})
        ServiceResponse.error(message: Array(message), payload: payload)
      end

      def error_no_permissions(payload: {})
        ServiceResponse.error(message: [INSUFFICIENT_PERMISSIONS_MESSAGE], payload: payload)
      end

      def track_ai_item_events(event_type, additional_properties = {})
        track_internal_event(
          event_type,
          user: current_user,
          project: project,
          additional_properties: additional_properties
        )
      end

      def item_execution_properties(item:, version:)
        Ai::Catalog::Tracking::EventPropertiesBuilder.new(item: item, version: version).to_h
      end

      # Builds the granular AI Catalog tracking properties for an item and
      # version. Merges in `label: item.item_type` to preserve the existing
      # event property for backward compatibility.
      def tracking_properties_for(item, version:)
        Ai::Catalog::Tracking::EventPropertiesBuilder
          .new(item: item, version: version)
          .to_h
          .merge(label: item.item_type)
      end

      def send_audit_events(event_type, item, params = {})
        messages = audit_event_messages(event_type, item, params)

        messages.each do |message|
          audit_context = {
            name: event_type,
            author: current_user,
            scope: project,
            target: item,
            target_details: "#{item.name} (ID: #{item.id})",
            message: message
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end

      def audit_event_messages(event_type, item, params)
        service_class = "::Ai::Catalog::#{item.item_type.to_s.camelize.pluralize}::" \
          "AuditEventMessageService".safe_constantize

        return [] if service_class.nil?

        service_class.new(event_type, item, params.merge(current_user: current_user)).messages
      end
    end
  end
end

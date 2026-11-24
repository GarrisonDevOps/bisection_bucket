# frozen_string_literal: true

module Ai
  module Catalog
    module ItemConsumers
      # Emits a DAP-specific audit event when a service account is auto-provisioned.
      # The generic `member_created` event is hard to distinguish from a regular user
      # being added, so this dedicated event provides clear auditing for compliance.
      class ServiceAccountProvisionedAuditor
        EVENT_NAME = 'duo_service_account_provisioned'

        def initialize(current_user:, service_account:, item:, item_consumer:)
          @current_user = current_user
          @service_account = service_account
          @item = item
          @item_consumer = item_consumer
        end

        def audit
          return if service_account.nil?

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        private

        attr_reader :current_user, :service_account, :item, :item_consumer

        def audit_context
          {
            name: EVENT_NAME,
            author: current_user,
            scope: scope,
            target: service_account,
            target_details: service_account.username,
            message: message,
            additional_details: additional_details.compact
          }
        end

        def scope
          item_consumer&.group || item_consumer&.project || service_account
        end

        def message
          msg = "Auto-provisioned Duo service account '#{service_account.username}' " \
            "for AI Catalog #{item_type || 'item'}"
          msg += " '#{item_name}'" if item_name.present?
          msg += " (foundational flow: #{foundational_reference})" if foundational_reference.present?
          msg
        end

        def additional_details
          {
            service_account_id: service_account.id,
            service_account_username: service_account.username,
            composite_identity_enforced: service_account.composite_identity_enforced?,
            provisioned_by_group_id: service_account.provisioned_by_group_id,
            item_id: item&.id,
            item_type: item_type,
            item_name: item_name,
            foundational_flow_reference: foundational_reference,
            item_consumer_id: item_consumer&.id,
            access_level: CreateService::SERVICE_ACCOUNT_ACCESS_LEVEL
          }
        end

        def item_name
          item&.name
        end

        def item_type
          item&.item_type
        end

        def foundational_reference
          item&.foundational_flow_reference
        end
      end
    end
  end
end

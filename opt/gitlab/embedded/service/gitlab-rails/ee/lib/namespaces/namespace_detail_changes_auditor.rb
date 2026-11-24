# frozen_string_literal: true

module Namespaces
  class NamespaceDetailChangesAuditor < ::AuditEvents::BaseChangesAuditor
    EVENT_NAME_PER_COLUMN = {
      description: 'group_description_updated'
    }.freeze

    def initialize(current_user, namespace_detail, group)
      @group = group

      super(current_user, namespace_detail)
    end

    def execute
      return if model.blank?

      EVENT_NAME_PER_COLUMN.each do |column, event_name|
        audit_changes(column, entity: @group, model: model, event_type: event_name)
      end
    end

    private

    def attributes_from_auditable_model(column)
      {
        from: model.previous_changes[column].first,
        to: model.previous_changes[column].last,
        target_details: @group.full_path
      }
    end
  end
end

# frozen_string_literal: true

module AuditEvents
  class GroupAuditEventFinder < BaseAuditEventFinder
    def initialize(group:, params: {})
      super(params: params)
      @group = group
    end

    private

    def init_collection
      ::AuditEvents::GroupAuditEvent.by_group(@group.id)
    end
  end
end

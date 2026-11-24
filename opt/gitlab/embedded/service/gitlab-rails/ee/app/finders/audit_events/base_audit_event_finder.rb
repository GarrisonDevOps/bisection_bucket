# frozen_string_literal: true

module AuditEvents
  class BaseAuditEventFinder
    include CreatedAtFilter
    include FinderMethods

    # Entity types accepted by the audit events REST API and by entity filtering.
    # These are scope class names, matching what the scoped models report as
    # `entity_type`.
    VALID_ENTITY_TYPES = %w[Project User Group Gitlab::Audit::InstanceScope].freeze

    def initialize(params: {})
      @params = params
    end

    def execute
      audit_events = init_collection
      audit_events = by_created_at(audit_events)
      audit_events = by_author(audit_events)

      if AuditEvents::OffsetOptimization.should_use_offset_optimization?(params)
        return AuditEvents::OffsetOptimization.paginate_with_offset_optimization(audit_events, params)
      end

      sort(audit_events)
    end

    private

    attr_reader :params, :optimize_offset

    def init_collection
      raise NotImplementedError, "Subclasses must define `init_collection`"
    end

    def by_author(audit_events)
      if valid_author_username?
        audit_events = audit_events.by_author_username(params[:author_username])
      elsif valid_author_id?
        audit_events = audit_events.by_author_id(params[:author_id])
      end

      audit_events
    end

    def sort(audit_events)
      audit_events.order_by(params[:sort], use_created_at: true)
    end

    def valid_author_id?
      params[:author_id].to_i.nonzero?
    end

    def valid_username?(username)
      username.present? && username.length >= User::MIN_USERNAME_LENGTH && username.length <= User::MAX_USERNAME_LENGTH
    end

    def valid_author_username?
      valid_username?(params[:author_username])
    end
  end
end

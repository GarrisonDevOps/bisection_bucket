# frozen_string_literal: true

module AuditEvents
  # Finder for retrieving audit events across multiple models with unified pagination.
  #
  # This finder combines audit events from four different models:
  # - InstanceAuditEvent (instance-wide events)
  # - UserAuditEvent (user-specific events)
  # - ProjectAuditEvent (project-specific events)
  # - GroupAuditEvent (group-specific events)
  #
  # Supports both keyset and offset-based pagination:
  # - Keyset pagination: Set `pagination: 'keyset'` with `cursor` and `per_page` parameters
  #   Orders by created_at DESC for chronological ordering
  # - Offset pagination: Set `pagination: 'offset'` (or any other value) with `page` and `per_page` parameters
  #   Orders by ID DESC for performance (or ID ASC if sort: 'created_asc')
  #   Note: Offset pagination uses ID ordering for performance reasons, which may differ from keyset ordering
  #
  # Example usage:
  #   # Keyset pagination
  #   finder = AuditEvents::CombinedAuditEventFinder.new(
  #     params: {
  #       entity_type: 'Project',
  #       author_id: 123,
  #       created_after: 1.week.ago,
  #       per_page: 20,
  #       cursor: 'eyJpZCI6MTIzfQ==',
  #       pagination: 'keyset'
  #     }
  #   )
  #   result = finder.execute
  #   # => { records: [...], cursor_for_next_page: '...' }
  #
  #   # Offset pagination
  #   finder = AuditEvents::CombinedAuditEventFinder.new(
  #     params: {
  #       entity_type: 'Project',
  #       author_id: 123,
  #       created_after: 1.week.ago,
  #       page: 20,
  #       per_page: 100,
  #       pagination: 'offset'
  #     }
  #   )
  #   result = finder.execute
  #   # => { records: [...], page: 20, per_page: 100 }
  class CombinedAuditEventFinder < BaseAuditEventFinder
    include FromUnion

    AUDIT_EVENT_MODELS = [
      AuditEvents::InstanceAuditEvent,
      AuditEvents::UserAuditEvent,
      AuditEvents::ProjectAuditEvent,
      AuditEvents::GroupAuditEvent
    ].freeze

    ENTITY_TYPE_TO_MODEL = {
      'User' => AuditEvents::UserAuditEvent,
      'Project' => AuditEvents::ProjectAuditEvent,
      'Group' => AuditEvents::GroupAuditEvent,
      'Gitlab::Audit::InstanceScope' => AuditEvents::InstanceAuditEvent
    }.freeze

    def initialize(params: {})
      super
      @per_page = params[:per_page]
      @cursor = params[:cursor]
      @page = params[:page]
      @pagination = params[:pagination]
      @sort = params[:sort] || 'created_desc'
    end

    # Executes the main query flow:
    # Determines pagination type and executes appropriate strategy
    def execute
      if pagination == 'keyset'
        execute_keyset_pagination
      else
        execute_offset_pagination
      end
    end

    def find(id)
      AUDIT_EVENT_MODELS.each do |model|
        audit_event = model.id_in(id).first
        return audit_event if audit_event
      end

      raise ActiveRecord::RecordNotFound
    end

    private

    attr_reader :per_page, :cursor, :page, :pagination, :sort

    # Keyset pagination implementation
    def execute_keyset_pagination
      scopes = build_model_scopes
      scopes = filter_scopes_by_entity_type(scopes) if params[:entity_type].present?
      keyset_scopes = build_keyset_scopes(scopes)
      union_results = execute_union_query(keyset_scopes)
      preloaded_records = preload_records(union_results)

      has_next_page = union_results.size > per_page
      next_cursor = has_next_page ? generate_next_cursor(preloaded_records) : nil

      { records: preloaded_records, cursor_for_next_page: next_cursor }
    end

    # Offset pagination implementation as specified:
    # 1. Build keyset paginated queries with only id and model name
    # 2. Add LIMIT based on page position
    # 3. Union and re-sort by id
    # 4. Apply OFFSET and LIMIT
    def execute_offset_pagination
      scopes = build_model_scopes
      scopes = filter_scopes_by_entity_type(scopes) if params[:entity_type].present?

      page_num = [page.to_i, 1].max
      page_size = [per_page.to_i, 1].max
      offset = (page_num - 1) * page_size

      max_position = (page_num * page_size) + 1

      offset_scopes = build_offset_scopes(scopes, max_position)

      union_results = execute_offset_union_query(offset_scopes, offset, page_size + 1)

      has_next_page = union_results.size > page_size

      preloaded_records = preload_records_offset(union_results, page_size)

      {
        records: preloaded_records,
        page: page_num,
        per_page: page_size,
        has_next_page: has_next_page
      }
    end

    def build_model_scopes
      AUDIT_EVENT_MODELS.map do |model|
        apply_filters(model.all).order_by('created_desc')
      end
    end

    def filter_scopes_by_entity_type(scopes)
      return scopes unless valid_entity_type?

      target_model = ENTITY_TYPE_TO_MODEL[params[:entity_type]]

      return scopes unless target_model

      scopes.select { |scope| scope.model == target_model }
    end

    def apply_filters(scope)
      scope = by_created_at(scope)
      scope = by_author(scope)
      scope = by_entity(scope)
      by_username(scope)
    end

    def by_username(audit_events)
      return audit_events unless params[:entity_username].present?
      return audit_events unless audit_events.model == AuditEvents::UserAuditEvent
      return audit_events unless params[:entity_type] == 'User'

      audit_events.by_username(params[:entity_username])
    end

    def build_keyset_scopes(scopes)
      return [] if scopes.empty?

      scopes.map do |scope|
        keyset_scope = build_keyset_order(scope)
        cursor_scope = apply_cursor_if_present(keyset_scope)
        add_select_and_limit(cursor_scope, scope.model)
      end
    end

    def build_offset_scopes(scopes, limit)
      return [] if scopes.empty?

      scopes.map do |scope|
        keyset_scope = build_keyset_order(scope)
        keyset_scope
          .limit(limit)
          .select(:id, "'#{scope.model}' AS ar_class")
      end
    end

    def build_keyset_order(scope)
      new_scope, success = Gitlab::Pagination::Keyset::SimpleOrderBuilder.build(scope)
      raise 'Failed to build keyset ordering' unless success

      new_scope
    end

    def apply_cursor_if_present(scope)
      return scope unless cursor

      cursor_conditions = parse_cursor_conditions
      return scope unless cursor_conditions

      order = Gitlab::Pagination::Keyset::Order.extract_keyset_order_object(scope)
      order.apply_cursor_conditions(scope, cursor_conditions)
    end

    def add_select_and_limit(scope, model)
      scope
        .limit(per_page + 1)
        .select(:id, :created_at, "'#{model}' AS ar_class")
    end

    def parse_cursor_conditions
      return unless cursor

      result = ::Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.parse(cursor)

      { id: result[:id] }
    end

    def execute_union_query(keyset_scopes)
      return [] if keyset_scopes.empty?

      base_model = AUDIT_EVENT_MODELS.first

      base_model
        .from_union(keyset_scopes, remove_order: false)
        .order_by('created_desc')
        .limit(per_page + 1)
        .to_a
    end

    def execute_offset_union_query(offset_scopes, offset, limit)
      return [] if offset_scopes.empty?

      base_model = AUDIT_EVENT_MODELS.first

      sort_order = sort == 'created_asc' ? :asc : :desc

      # rubocop: disable CodeReuse/ActiveRecord -- complex query building, not used anywhere else.
      base_model
        .from_union(offset_scopes, remove_order: false)
        .reorder(id: sort_order)
        .offset(offset)
        .limit(limit)
        .to_a
      # rubocop: enable CodeReuse/ActiveRecord
    end

    # Preloads full audit event records from their respective tables.
    # The UNION query only selects minimal columns (id, created_at, ar_class),
    # so we need to load the complete records using (created_at, id) pairs
    # for efficient batching.
    def preload_records(union_results)
      records_to_load = union_results.first(per_page)
      return [] if records_to_load.empty?

      grouped_records = records_to_load.group_by(&:ar_class)
      sorted_index = create_sorted_index(records_to_load)
      preloaded_records = load_grouped_records(grouped_records)

      preloaded_records.sort_by { |record| sorted_index[record.id] || Float::INFINITY }
    end

    # Preload records for offset pagination
    def preload_records_offset(union_results, limit)
      return [] if union_results.empty?

      # Only take the requested number of records
      records_to_load = union_results.first(limit)

      grouped_records = records_to_load.group_by(&:ar_class)
      sorted_index = create_sorted_index(records_to_load)
      preloaded_records = load_grouped_records_by_id(grouped_records)

      preloaded_records.sort_by { |record| sorted_index[record.id] || Float::INFINITY }
    end

    def create_sorted_index(records)
      records.each_with_index.to_h { |record, index| [record.id, index] }
    end

    def load_grouped_records(grouped_records)
      grouped_records.flat_map do |ar_class_name, record_group|
        model_class = ar_class_name.constantize
        load_records_by_pairs(model_class, record_group).to_a
      end
    end

    # Load records by ID only (for offset pagination)
    def load_grouped_records_by_id(grouped_records)
      grouped_records.flat_map do |ar_class_name, record_group|
        model_class = ar_class_name.constantize
        ids = record_group.map(&:id)
        model_class.id_in(ids).to_a
      end
    end

    def load_records_by_pairs(model_class, records)
      return model_class.none if records.empty?

      value_pairs = records.map { |r| [r.created_at.utc, r.id] }
      placeholders = build_placeholders(value_pairs.size)
      where_clause = "(created_at, id) IN (#{placeholders})"

      model_class.where(where_clause, *value_pairs.flatten) # rubocop: disable CodeReuse/ActiveRecord -- complex query building, not used anywhere else.
    end

    def build_placeholders(count)
      (['(?, ?)'] * count).join(', ')
    end

    def generate_next_cursor(records)
      return if records.empty?

      last_record = records.last
      cursor_attributes = {
        id: last_record.id
      }

      ::Gitlab::Pagination::Keyset::Paginator::Base64CursorConverter.dump(cursor_attributes)
    end

    def by_entity(audit_events)
      return audit_events unless valid_entity_id?

      model_class = audit_events.model

      case model_class.name
      when 'AuditEvents::UserAuditEvent'
        return audit_events unless params[:entity_type] == 'User'

        audit_events.by_user(params[:entity_id])
      when 'AuditEvents::ProjectAuditEvent'
        return audit_events unless params[:entity_type] == 'Project'

        audit_events.by_project(params[:entity_id])
      when 'AuditEvents::GroupAuditEvent'
        return audit_events unless params[:entity_type] == 'Group'

        audit_events.by_group(params[:entity_id])
      else
        audit_events
      end
    end

    def valid_entity_type?
      VALID_ENTITY_TYPES.include?(params[:entity_type])
    end

    def valid_entity_id?
      params[:entity_id].to_i.nonzero?
    end
  end
end

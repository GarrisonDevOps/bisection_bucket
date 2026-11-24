# frozen_string_literal: true

module Vulnerabilities
  module DetailSanitizer
    extend ActiveSupport::Concern

    BASE_KEYS = %w[type field_name name description].freeze

    # Allowed keys per type are derived from the JSON schema at
    # ee/app/validators/json_schemas/vulnerability_finding_details.json
    ALLOWED_KEYS_BY_TYPE = {
      'text' => (BASE_KEYS + %w[value]).freeze,
      'url' => (BASE_KEYS + %w[href text]).freeze,
      'code' => (BASE_KEYS + %w[value lang]).freeze,
      'diff' => (BASE_KEYS + %w[before after]).freeze,
      'list' => (BASE_KEYS + %w[items]).freeze,
      'named-list' => (BASE_KEYS + %w[items]).freeze,
      'commit' => (BASE_KEYS + %w[value]).freeze,
      'markdown' => (BASE_KEYS + %w[value]).freeze,
      'file-location' => (BASE_KEYS + %w[file_name line_start line_end]).freeze,
      'module-location' => (BASE_KEYS + %w[module_name offset]).freeze,
      'boolean' => (BASE_KEYS + %w[value]).freeze,
      'integer' => (BASE_KEYS + %w[value]).freeze,
      'table' => (BASE_KEYS + %w[header rows]).freeze,
      'code-flows' => (BASE_KEYS + %w[items]).freeze,
      'code-flow-node' => (BASE_KEYS + %w[node_type file_location]).freeze,
      'value' => (BASE_KEYS + %w[value]).freeze
    }.freeze

    def sanitize_detail(detail)
      type = detail['type'].to_s
      allowed_keys = ALLOWED_KEYS_BY_TYPE[type] || BASE_KEYS

      log_stripped_keys(type, detail.keys.map(&:to_s) - allowed_keys)
      sanitize_nested(detail.slice(*allowed_keys), type)
    end

    private

    def log_stripped_keys(type, stripped_keys)
      return unless stripped_keys.any?

      Gitlab::AppJsonLogger.warn(
        message: 'Unexpected keys stripped from vulnerability detail',
        detail_type: type,
        stripped_keys: stripped_keys
      )
    end

    def sanitize_nested(sanitized, type)
      case type
      when 'table' then sanitize_table(sanitized)
      when 'list' then sanitize_list(sanitized)
      when 'code-flows' then sanitize_code_flows(sanitized)
      when 'named-list' then sanitize_named_list(sanitized)
      when 'code-flow-node' then sanitize_code_flow_node(sanitized)
      end

      sanitized
    end

    def sanitize_table(sanitized)
      sanitized['header'] = sanitized['header'].map { |h| sanitize_if_hash(h) } if sanitized['header'].is_a?(Array)

      return unless sanitized['rows'].is_a?(Array)

      sanitized['rows'] = sanitized['rows'].map do |row|
        row.is_a?(Array) ? row.map { |cell| sanitize_if_hash(cell) } : row
      end
    end

    def sanitize_list(sanitized)
      return unless sanitized['items'].is_a?(Array)

      sanitized['items'] = sanitized['items'].map { |item| sanitize_if_hash(item) }
    end

    def sanitize_code_flows(sanitized)
      return unless sanitized['items'].is_a?(Array)

      sanitized['items'] = sanitized['items'].map do |flow|
        flow.is_a?(Array) ? flow.map { |node| sanitize_if_hash(node) } : flow
      end
    end

    def sanitize_code_flow_node(sanitized)
      sanitized['file_location'] = sanitize_if_hash(sanitized['file_location'])
    end

    def sanitize_named_list(sanitized)
      return unless sanitized['items'].is_a?(Hash)

      sanitized['items'] = sanitized['items'].transform_values { |item| sanitize_if_hash(item) }
    end

    def sanitize_if_hash(item)
      item.is_a?(Hash) ? sanitize_detail(item) : item
    end
  end
end

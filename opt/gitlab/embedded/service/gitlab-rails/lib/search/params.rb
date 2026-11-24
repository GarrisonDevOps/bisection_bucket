# frozen_string_literal: true

module Search
  class Params
    include ActiveModel::Validations

    SEARCH_CHAR_LIMIT = 4096
    SEARCH_TERM_LIMIT = 64
    MIN_TERM_LENGTH = 2
    BOOLEAN_PARAMS = %i[confidential exclude_forks include_archived].freeze
    # Coerced to Time before they reach a backend: an uncoerced value either
    # raises in the PostgreSQL finders or is a 400 from Elasticsearch.
    DATE_PARAMS = %i[created_after created_before updated_after updated_before].freeze
    # The subset the basic (PostgreSQL) path also applies: created_at is that
    # query's sort key, so its range rides the index scan already performed.
    # updated_at leads no index, so a range there walks the whole scan.
    BASIC_SEARCH_DATE_PARAMS = %i[created_after created_before].freeze
    MAX_ASSIGNEE_IDS = 20
    ASSIGNEE_ID_PARAMS = %i[assignee_ids not_assignee_ids].freeze
    LEGACY_SCOPE_MAP = {
      'issues' => 'work_items'
    }.freeze

    # Generic validation
    validates :query_string, length: { maximum: SEARCH_CHAR_LIMIT }
    validate :not_too_many_terms
    validate :date_params_parseable
    validate :assignee_ids_within_limit
    validate :assignee_ids_well_formed

    attr_reader :raw_params, :query_string, :abuse_detection
    alias_method :search, :query_string
    alias_method :term, :query_string

    def initialize(params, detect_abuse: true)
      @invalid_date_params = []
      @raw_params      = process_params(params)
      @query_string    = strip_surrounding_whitespace(@raw_params[:search] || @raw_params[:term])
      @detect_abuse    = detect_abuse
      @abuse_detection = ::Gitlab::Search::AbuseDetection.new(self) if @detect_abuse

      validate
    end

    def [](key)
      if respond_to? key
        # We have this logic here to support reading custom attributes
        # like @query_string
        #
        # This takes precedence over values in @raw_params
        public_send(key) # rubocop:disable GitlabSecurity/PublicSend -- metaprogramming is needed
      else
        raw_params[key]
      end
    end

    def slice(*keys)
      keys.index_with { |key| self[key] }.with_indifferent_access
    end

    def abusive?
      detect_abuse? && abuse_detection.errors.any?
    end

    def valid_query_length?
      return true unless errors.has_key? :query_string

      errors[:query_string].none? { |msg| msg.include? SEARCH_CHAR_LIMIT.to_s }
    end

    def valid_terms_count?
      return true unless errors.has_key? :query_string

      errors[:query_string].none? { |msg| msg.include? SEARCH_TERM_LIMIT.to_s }
    end

    # Invalid dates are dropped from raw_params, so a caller that ignores this
    # still never forwards a malformed value to a backend.
    def valid_date_params?
      invalid_date_params.empty?
    end

    def invalid_date_params
      @invalid_date_params ||= []
    end

    # Unlike the dates above, oversized lists stay in raw_params, so a caller
    # that ignores this fails closed rather than searching a truncated list.
    def valid_assignee_ids?
      oversized_assignee_id_params.empty? && malformed_assignee_id_params.empty?
    end

    def oversized_assignee_id_params
      @oversized_assignee_id_params ||= ASSIGNEE_ID_PARAMS.select do |key|
        Array(raw_params[key]).size > MAX_ASSIGNEE_IDS
      end
    end

    # A Hash-shaped value (e.g. `assignee_ids[0]=5`) survives Array.wrap intact.
    def malformed_assignee_id_params
      @malformed_assignee_id_params ||= ASSIGNEE_ID_PARAMS.select do |key|
        Array(raw_params[key]).any? { |id| id.respond_to?(:to_h) }
      end
    end

    def email_lookup?
      search_terms.any? { |term| term =~ URI::MailTo::EMAIL_REGEXP }
    end

    def validate
      abuse_detection.validate if detect_abuse?

      super
    end

    private

    def legacy_scope_map
      LEGACY_SCOPE_MAP
    end

    def detect_abuse?
      @detect_abuse
    end

    def search_terms
      @search_terms ||= query_string.split
    end

    def not_too_many_terms
      return unless search_terms.count > SEARCH_TERM_LIMIT

      errors.add :query_string, "has too many search terms (maximum is #{SEARCH_TERM_LIMIT})"
    end

    def strip_surrounding_whitespace(obj)
      obj.to_s.strip
    end

    def process_params(params)
      processed_params = params.is_a?(Hash) ? params.with_indifferent_access : params.dup
      processed_params = convert_legacy_scope(processed_params)
      processed_params = convert_all_boolean_params(processed_params)
      processed_params = convert_all_date_params(processed_params)
      processed_params = convert_type_to_ids(processed_params)
      processed_params = convert_not_params(processed_params)
      convert_all_assignee_id_params(processed_params)
    end

    def convert_legacy_scope(params)
      return params unless params[:scope].present?
      # Skip conversion for API requests to maintain backward compatibility
      return params if params[:skip_legacy_scope_conversion]

      legacy_scope = params[:scope].to_s
      return params.merge(scope: legacy_scope_map[legacy_scope]) if legacy_scope_map.key?(legacy_scope)

      params
    end

    def convert_not_params(params)
      not_params = params.delete(:not)
      return params unless not_params&.respond_to?(:to_h)

      not_params.each do |key, value|
        params[:"not_#{key}"] = value
      end

      params
    end

    def convert_all_boolean_params(params)
      BOOLEAN_PARAMS.each do |key|
        params[key] = ::Gitlab::Utils.to_boolean(params[key]) if params.key?(key)
      end

      params
    end

    # A scalar assignee_ids value (no `[]`) reaches the ES filter builder's
    # `.map` call and raises NoMethodError there instead of here.
    def convert_all_assignee_id_params(params)
      ASSIGNEE_ID_PARAMS.each do |key|
        params[key] = Array.wrap(params[key]) if params.key?(key)
      end

      params
    end

    # Mirrors the REST API, which declares these as `type: DateTime` and lets
    # Grape reject a bad value. A blank value is absent, not an error.
    def convert_all_date_params(params)
      DATE_PARAMS.each do |key|
        next unless params.key?(key)

        value = params[key]

        if value.blank?
          params.delete(key)
          next
        end

        coerced = coerce_to_time(value)

        if coerced.nil?
          invalid_date_params << key
          params.delete(key)
        else
          params[key] = coerced
        end
      end

      params
    end

    def coerce_to_time(value)
      return value if value.is_a?(Time) || value.is_a?(DateTime)
      # A Date carries no time component, so widen it to midnight in the
      # request's zone rather than returning something that is not a Time.
      return value.in_time_zone if value.is_a?(Date)

      # ::Time.zone.iso8601 keeps the request's zone (unlike Time.iso8601)
      # but also accepts omitted seconds, so require them explicitly to
      # keep the no-seconds form rejected.
      return coerce_date_only(value) unless value.to_s.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/)

      ::Time.zone.iso8601(value.to_s)
    rescue ArgumentError
      coerce_date_only(value)
    end

    # Only a plain YYYY-MM-DD falls back here; a value carrying a time part
    # (e.g. "2026-01-01T10:00Z") would otherwise silently lose that time.
    def coerce_date_only(value)
      return unless value.to_s.match?(/\A\d{4}-\d{2}-\d{2}\z/)

      Date.iso8601(value.to_s).in_time_zone
    rescue ArgumentError, TypeError
      nil
    end

    def date_params_parseable
      return if invalid_date_params.empty?

      invalid_date_params.each do |key|
        errors.add key, 'must be a valid date'
      end
    end

    def assignee_ids_within_limit
      oversized_assignee_id_params.each do |key|
        errors.add key, "has too many IDs (maximum is #{MAX_ASSIGNEE_IDS})"
      end
    end

    def assignee_ids_well_formed
      malformed_assignee_id_params.each do |key|
        errors.add key, 'must be a list of IDs'
      end
    end

    def convert_type_to_ids(params)
      return params unless params[:type].present?

      provider = ::WorkItems::TypesFramework::Provider.new
      # Downcase type names to support case-insensitive filtering
      # (e.g., "TASK", "Task", and "task" should all work)
      normalized_types = Array(params[:type]).map { |type| type.to_s.downcase }
      params[:work_item_type_ids] = provider.ids_by_base_types(normalized_types)
      params.delete(:type)
      params
    end
  end
end

Search::Params.prepend_mod

# frozen_string_literal: true

module Ci
  # A virtual model representing a pipeline variable. Used when pipeline
  # variables are handled in a non-DB storage context (e.g. object storage).
  class PipelineVariableItem
    include ActiveModel::Model
    include ActiveModel::Attributes
    include ActiveModel::Validations
    include GlobalID::Identification
    include Gitlab::Utils::StrongMemoize

    VARIABLE_TYPES = Enums::Ci::Variable::TYPES.keys.map(&:to_s).freeze
    MAX_KEY_LENGTH = 255
    # Absolute backstop that still applies when the plan limit is 0.
    MAX_VALUE_LENGTH = 500_000_000
    OVERRIDE_FILE_VALUE_SIZE = 10.megabytes

    def self.limits_doc_link
      Rails.application.routes.url_helpers.help_page_url('ci/variables/_index.md', anchor: 'pipeline-variable-limits')
    end

    attribute :key, :string
    attribute :value, :string
    attribute :variable_type, :string, default: 'env_var'
    attribute :raw, :boolean, default: false

    validates :key,
      presence: true,
      length: { maximum: MAX_KEY_LENGTH },
      format: { with: /\A[a-zA-Z0-9_]+\z/,
                message: "can contain only letters, digits and '_'." }

    # A lambda, so specs can stub the constant.
    validates :value, length: { maximum: -> { MAX_VALUE_LENGTH } }
    validates :variable_type, inclusion: { in: VARIABLE_TYPES }
    validates :raw, inclusion: { in: [true, false] }
    validate :value_within_size_limit

    alias_method :raw?, :raw

    # Required for auth check in Types::Ci::PipelineManualVariableType
    attr_reader :pipeline

    def initialize(pipeline:, **kwargs)
      @pipeline = pipeline

      super(**kwargs)
    end

    def key=(value)
      super(value.to_s.strip)
    end

    def variable_type=(value)
      # To mimic Ci::PipelineVariable variable_type enum behaviour
      if value.is_a?(Integer)
        enum_map = Enums::Ci::Variable::TYPES.invert
        value = enum_map[value]
      end

      super(value&.to_s)
    end

    # An ID is required for Types::Ci::PipelineManualVariableType
    def id
      Digest::SHA256.hexdigest("#{pipeline.id}/#{key}")
    end
    strong_memoize_attr :id

    def to_hash_variable
      { key: key, value: value, public: false, file: file?, raw: raw }
    end

    def file?
      variable_type == 'file'
    end

    def hook_attrs
      { key: key, value: value }
    end

    private

    def value_within_size_limit
      # An invalid key is echoed back in the message below, so skip it until it is known safe.
      return if errors[:key].any?

      return if size_limit == 0
      return if value.to_s.bytesize <= size_limit

      limit = override_size_limit
      return if value.to_s.bytesize <= limit

      errors.add(:base, format(
        _('Value for variable %{key} exceeds the %{limit} limit. For more information, see %{link}'),
        key: key, limit: ActiveSupport::NumberHelper.number_to_human_size(limit), link: self.class.limits_doc_link
      ))
    end

    # Read only once a value is over the plan limit, so most pipelines never check the flag.
    def override_size_limit
      return size_limit unless file? && size_limit < OVERRIDE_FILE_VALUE_SIZE
      return size_limit unless override_enabled?

      OVERRIDE_FILE_VALUE_SIZE
    end

    def override_enabled?
      ::Feature.enabled?(:ci_pipeline_variable_limits_override, pipeline.project.root_namespace, type: :ops)
    end

    def size_limit
      limits = pipeline.project&.actual_limits
      return 0 unless limits

      file? ? limits.ci_variable_file_value_size : limits.ci_variable_value_size
    end
    strong_memoize_attr :size_limit
  end
end

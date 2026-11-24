# frozen_string_literal: true

module Security
  class ProjectSecurityExclusion < ::SecApplicationRecord
    self.inheritance_column = :_type_disabled

    # Maximum number of path-based exclusions per project. This is an arbitrary limit aimed to
    # prevent single project from having a huge number of path exclusions causing performance issues,
    # and also to discourage users from using exclusions in favor of actually removing secrets.
    #
    # See discussion: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/166511#note_2138495926.
    MAX_PATH_EXCLUSIONS_PER_PROJECT = 10

    belongs_to :project

    enum :scanner, { secret_push_protection: 0 }
    enum :type, { path: 0, regex_pattern: 1, raw_value: 2, rule: 3 }

    EXCLUSION_TYPE_MAP = {
      'rule' => :EXCLUSION_TYPE_RULE,
      'path' => :EXCLUSION_TYPE_PATH,
      'raw_value' => :EXCLUSION_TYPE_RAW_VALUE,
      'unknown' => :EXCLUSION_TYPE_UNSPECIFIED
    }.freeze

    validates :scanner, :type, :value, :project, presence: true
    validates :active, inclusion: { in: [true, false] }
    validates :value, :description, length: { maximum: 255 }

    validate :validate_push_protection_path_exclusions_limit, if: -> do
      scanner == 'secret_push_protection' && type == 'path'
    end

    scope :by_scanner, ->(scanner) { where(scanner: scanner) }
    scope :by_type, ->(type) { where(type: type) }
    scope :by_status, ->(status) { where(active: status) }
    scope :active, -> { by_status(true) }

    def audit_details
      attributes.slice('scanner', 'value', 'active', 'description').symbolize_keys
    end

    def exclusion_type
      EXCLUSION_TYPE_MAP.fetch(type, ::Gitlab::SecretDetection::GRPC::ExclusionType::EXCLUSION_TYPE_UNSPECIFIED)
    end

    private

    def validate_push_protection_path_exclusions_limit
      validate_push_protection_path_exclusions_count = project.security_exclusions
                                                        .by_scanner(:secret_push_protection)
                                                        .by_type(:path)
                                                        .where.not(id: id)
                                                        .count

      return unless validate_push_protection_path_exclusions_count >= MAX_PATH_EXCLUSIONS_PER_PROJECT

      errors.add(
        :base,
        format(
          _("Cannot have more than %{maximum_path_exclusions} path exclusions for secret push protection per project"),
          maximum_path_exclusions: MAX_PATH_EXCLUSIONS_PER_PROJECT
        )
      )
    end
  end
end

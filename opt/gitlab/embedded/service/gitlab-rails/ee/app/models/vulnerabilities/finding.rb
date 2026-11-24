# frozen_string_literal: true

module Vulnerabilities
  class Finding < ::SecApplicationRecord
    extend EnforceVulnerabilityReadDbTriggerFf
    include Ci::Partitionable::AssociationFinder
    include ShaAttribute
    include ::Gitlab::Utils::StrongMemoize
    include Presentable
    include ::VulnerabilityFindingHelpers
    include PolicyAutoDismissable
    include PolicySeverityOverridable
    include Security::CveEnrichmentFilterable
    include Vulnerabilities::DetailSanitizer
    include Vulnerabilities::SecretDetectionSha

    # https://gitlab.com/groups/gitlab-org/-/epics/3148
    # https://gitlab.com/gitlab-org/gitlab/-/issues/214563#note_370782508 is why the table names are not renamed
    self.table_name = 'vulnerability_occurrences'

    FINDINGS_PER_PAGE = 20
    MAX_NUMBER_OF_IDENTIFIERS = 20
    REPORT_TYPES_WITH_LOCATION_IMAGE = %w[container_scanning cluster_image_scanning].freeze
    SECRET_DETECTION_DEFAULT_COMMIT_SHA = "0000000"

    AI_ALLOWED_REPORT_TYPES = %w[sast].freeze

    # https://gitlab.com/gitlab-org/gitlab/-/issues/472861
    HIGH_CONFIDENCE_AI_RESOLUTION_CWES = %w[
      CWE-23
      CWE-73
      CWE-78
      CWE-80
      CWE-89
      CWE-116
      CWE-118
      CWE-119
      CWE-120
      CWE-126
      CWE-190
      CWE-200
      CWE-208
      CWE-209
      CWE-272
      CWE-287
      CWE-295
      CWE-297
      CWE-305
      CWE-310
      CWE-311
      CWE-323
      CWE-327
      CWE-328
      CWE-330
      CWE-338
      CWE-345
      CWE-346
      CWE-352
      CWE-362
      CWE-369
      CWE-377
      CWE-378
      CWE-400
      CWE-489
      CWE-521
      CWE-539
      CWE-599
      CWE-611
      CWE-676
      CWE-704
      CWE-754
      CWE-770
      CWE-1004
      CWE-1275
    ].to_set.freeze

    paginates_per FINDINGS_PER_PAGE

    sha_attribute :location_fingerprint

    attr_readonly :initial_pipeline_id

    belongs_to :project, inverse_of: :vulnerability_findings
    belongs_to :scanner, class_name: 'Vulnerabilities::Scanner'
    belongs_to :primary_identifier, class_name: 'Vulnerabilities::Identifier', inverse_of: :primary_findings
    belongs_to :vulnerability, class_name: 'Vulnerability', inverse_of: :findings
    has_one :one_vulnerability, class_name: 'Vulnerability', inverse_of: :vulnerability_finding
    has_many :state_transitions, through: :vulnerability
    has_many :issue_links, through: :vulnerability
    has_many :external_issue_links, class_name: 'Vulnerabilities::ExternalIssueLink', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'
    has_many :merge_request_links, through: :vulnerability

    has_many :finding_identifiers, class_name: 'Vulnerabilities::FindingIdentifier', inverse_of: :finding, foreign_key: 'occurrence_id'
    has_many :identifiers, through: :finding_identifiers, class_name: 'Vulnerabilities::Identifier'

    has_many :cve_identifiers, -> { where('LOWER(external_type) = ?', 'cve') }, through: :finding_identifiers, source: :identifier, class_name: 'Vulnerabilities::Identifier'
    has_many :cve_enrichments, through: :cve_identifiers, disable_joins: true

    has_one :finding_token_status, class_name: 'Vulnerabilities::FindingTokenStatus', foreign_key: 'vulnerability_occurrence_id', inverse_of: :finding

    has_many :finding_links, class_name: 'Vulnerabilities::FindingLink', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'

    has_many :finding_remediations, class_name: 'Vulnerabilities::FindingRemediation', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'
    has_many :remediations, through: :finding_remediations

    has_many :triggered_workflows, class_name: '::Vulnerabilities::TriggeredWorkflow', inverse_of: :vulnerability_occurrence, foreign_key: 'vulnerability_occurrence_id'

    has_one :finding_risk_score, class_name: 'Vulnerabilities::FindingRiskScore', inverse_of: :finding

    has_one :flip_guard, class_name: 'Vulnerabilities::FlipGuard', inverse_of: :finding, foreign_key: 'vulnerability_finding_id'

    # rubocop: disable Rails/InverseOf -- these relations are not present on Ci::Pipeline
    belongs_to :initial_finding_pipeline, class_name: '::Ci::Pipeline', foreign_key: 'initial_pipeline_id'
    belongs_to :latest_finding_pipeline, class_name: '::Ci::Pipeline', foreign_key: 'latest_pipeline_id'
    # rubocop:enable Rails/InverseOf
    partitionable_belongs_to_loader :initial_finding_pipeline
    partitionable_belongs_to_loader :latest_finding_pipeline

    has_many :signatures, class_name: 'Vulnerabilities::FindingSignature', inverse_of: :finding

    has_many :vulnerability_flags, class_name: 'Vulnerabilities::Flag', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'

    has_many :feedbacks, class_name: 'Vulnerabilities::Feedback', inverse_of: :finding, primary_key: 'uuid', foreign_key: 'finding_uuid'

    has_one :finding_evidence, class_name: 'Vulnerabilities::Finding::Evidence', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'

    has_one :ascp_component_link, class_name: 'Vulnerabilities::AscpComponentLink',
      foreign_key: :vulnerability_occurrence_id, inverse_of: :vulnerability_finding
    has_one :ascp_component, through: :ascp_component_link, class_name: 'Security::Ascp::Component'

    has_many :detection_transitions, class_name: 'Vulnerabilities::DetectionTransition', inverse_of: :finding, foreign_key: 'vulnerability_occurrence_id'

    has_many :security_findings,
      class_name: 'Security::Finding',
      primary_key: :uuid,
      foreign_key: :uuid,
      inverse_of: :vulnerability_finding

    has_many :security_finding_enrichments,
      class_name: 'Security::FindingEnrichment',
      inverse_of: :vulnerability_finding,
      primary_key: 'uuid',
      foreign_key: 'finding_uuid'

    has_one :finding_due_date,
      class_name: 'Vulnerabilities::FindingDueDate',
      foreign_key: :vulnerability_occurrence_id,
      inverse_of: :finding

    has_one :finding_custom_risk_score,
      class_name: 'Vulnerabilities::FindingCustomRiskScore',
      foreign_key: :vulnerability_occurrence_id,
      inverse_of: :finding

    belongs_to :project_tracked_context,
      class_name: 'Security::ProjectTrackedContext',
      foreign_key: 'security_project_tracked_context_id',
      inverse_of: false

    attribute :config_options, ::Gitlab::Database::Type::IndifferentJsonb.new

    attr_writer :sha
    attr_accessor :scan, :found_by_pipeline

    enum :report_type, ::Enums::Vulnerability.report_types
    enum :severity, ::Enums::Vulnerability.severity_levels, prefix: :severity
    enum :detection_method, ::Enums::Vulnerability.detection_methods

    before_save :sanitize_details

    validates :scanner, presence: true
    validates :project, presence: true
    validates :uuid, presence: true

    validates :primary_identifier, presence: true
    validates :location_fingerprint, presence: true, length: { maximum: 64 }
    # Uniqueness validation doesn't work with binary columns, so save this useless query. It is enforce by DB constraint anyway.
    # TODO: find out why it fails
    # validates :location_fingerprint, presence: true, uniqueness: { scope: [:primary_identifier_id, :scanner_id, :ref, :pipeline_id, :project_id] }
    validates :name, presence: true
    validates :report_type, presence: true
    validates :severity, presence: true
    validates :detection_method, presence: true

    validates :metadata_version, presence: true
    validates :raw_metadata, presence: true
    validates :details, json_schema: { filename: 'vulnerability_finding_details' }

    COLUMN_LENGTH_LIMITS = {
      description: 15_000,
      solution: 7_000
    }.freeze

    validates :description, length: { maximum: COLUMN_LENGTH_LIMITS[:description] }
    validates :solution, length: { maximum: COLUMN_LENGTH_LIMITS[:solution] }
    validates :cve, length: { maximum: 48400 }

    delegate :name, :external_id, to: :scanner, prefix: true, allow_nil: true

    scope :report_type, ->(type) { where(report_type: report_types[type]) }
    scope :ordered, -> { order(severity: :desc, id: :asc) }

    scope :active, -> { joins(:vulnerability).merge(Vulnerability.active) }
    scope :by_vulnerability, ->(vulnerability_id) { where(vulnerability: vulnerability_id) }
    scope :by_report_types, ->(values) { where(report_type: values) }
    scope :by_projects, ->(values) { where(project_id: values) }
    scope :by_scanners, ->(values) { where(scanner_id: values) }
    scope :by_severities, ->(values) { where(severity: values) }
    scope :by_location_fingerprints, ->(values) { where(location_fingerprint: values) }
    scope :by_uuid, ->(uuids) { where(uuid: uuids) }
    scope :excluding_uuids, ->(uuids) { where.not(uuid: uuids) }
    scope :eager_load_comparison_entities, -> { includes(:scanner, :primary_identifier, :project_tracked_context) }
    scope :by_primary_identifiers, ->(identifier_ids) { where(primary_identifier: identifier_ids) }
    scope :by_latest_pipeline, ->(pipeline_id) { where(latest_pipeline_id: pipeline_id) }
    scope :with_project, -> { includes(:project) }
    scope :with_token_status, -> { preload(:finding_token_status) }
    scope :with_cve_enrichments, -> { includes(:cve_enrichments) }
    scope :with_cve_identifiers, -> { includes(:cve_identifiers) }
    scope :with_risk_score, -> { preload(:finding_risk_score) }

    scope :all_preloaded, -> do
      preload(:scanner, :identifiers, :feedbacks, project: [:namespace, :project_feature])
    end

    scope :with_false_positive, ->(false_positive, min_confidence: nil) do
      flags = ::Vulnerabilities::Flag.arel_table

      subquery = ::Vulnerabilities::Flag.select(1).false_positive
      subquery = subquery.where(flags[:confidence_score].gt(min_confidence)) if min_confidence

      where(
        false_positive ? 'EXISTS (?)' : 'NOT EXISTS (?)',
        subquery.where(flags[:vulnerability_occurrence_id].eq(arel_table[:id]))
      )
    end

    scope :with_latest_detection_transition, -> do
      last_detection_transition = Vulnerabilities::DetectionTransition.where(arel_table[:id].eq(Vulnerabilities::DetectionTransition.arel_table[:vulnerability_occurrence_id])).order(id: :desc).limit(1)
      includes(:detection_transitions).where(detection_transitions: { id: last_detection_transition })
    end

    scope :with_stale_detection_transition, -> do
      where(
        'EXISTS (
          SELECT 1
          FROM (
            SELECT id, detected
            FROM vulnerability_detection_transitions latest
            WHERE latest.vulnerability_occurrence_id = vulnerability_occurrences.id
            ORDER BY id DESC
            LIMIT 1
          ) vdt
          WHERE vdt.detected = FALSE
        )'
      )
    end

    def self.by_vulnerability_with_stale_detection_transition(vulnerability_ids)
      by_vulnerability(vulnerability_ids)
        .with_stale_detection_transition
    end

    def self.lock_for_confirmation!(project:, id:)
      project.vulnerability_findings.where(vulnerability_id: nil).lock.find(id)
    end

    # A scanner placeholder solution ("Unfortunately, there is no solution available...")
    # counts as no solution.
    scope :with_fix_available, ->(fix_available) do
      remediation = ::Vulnerabilities::FindingRemediation.arel_table
      placeholder = ::DependencyManagement::SecurityUpdate::Eligibility::UNKNOWN_SOLUTION_SQL_REGEX

      solution_query = if fix_available
                         where("vulnerability_occurrences.solution IS NOT NULL AND vulnerability_occurrences.solution <> ''")
                           .where('vulnerability_occurrences.solution !~* ?', placeholder)
                       else
                         where("(vulnerability_occurrences.solution IS NULL OR vulnerability_occurrences.solution = '')")
                           .or(where('vulnerability_occurrences.solution ~* ?', placeholder))
                       end

      exist_query = where(
        fix_available ? 'EXISTS (?)' : 'NOT EXISTS (?)',
        ::Vulnerabilities::FindingRemediation.select(1).where(remediation[:vulnerability_occurrence_id].eq(arel_table[:id]))
      )

      fix_available ? solution_query.or(exist_query) : solution_query.and(exist_query)
    end

    scope :by_location_image, ->(images) do
      where(report_type: REPORT_TYPES_WITH_LOCATION_IMAGE)
        .where("vulnerability_occurrences.location -> 'image' ?| array[:images]", images: images)
    end
    scope :by_location_cluster, ->(cluster_ids) do
      where(report_type: 'cluster_image_scanning')
        .where("vulnerability_occurrences.location -> 'kubernetes_resource' -> 'cluster_id' ?| array[:cluster_ids]", cluster_ids: cluster_ids)
    end
    scope :by_location_cluster_agent, ->(agent_ids) do
      where(report_type: 'cluster_image_scanning')
        .where("vulnerability_occurrences.location -> 'kubernetes_resource' -> 'agent_id' ?| array[:agent_ids]", agent_ids: agent_ids)
    end
    scope :with_detected_as_fp_flag, -> do
      joins(:vulnerability_flags)
        .merge(
          ::Vulnerabilities::Flag
            .false_positive
            .last_false_positive_per_finding
            .with_status(:detected_as_fp)
        )
    end

    alias_method :declarative_policy_subject, :project
    alias_attribute :finding_details, :details
    alias_attribute :context_unaware_uuid, :new_uuid

    # sha can be sourced from a joined pipeline or set from the report
    def sha
      # Some analysers (like Secret Detection) that produce security findings may perform scans across Git history and
      # attach specific commit information to the finding. When this is the case, we _must_ use the commit SHA specified
      # in the security report to compute the blob URL, otherwise the URL will link to the incorrect revision of the file.
      #
      # We also need to ensure we _don't_ use the commit SHA from the report if it's the default placeholder value,
      # which is defined in the `secrets` analyzer:
      # https://gitlab.com/gitlab-org/security-products/analyzers/secrets/-/blob/7e1e03209495a209308f3e9e96c5a4a0d32e1d55/secret.go#L13-13
      secret_detection_sha || @sha || pipeline_branch
    end

    def state
      if vulnerability.nil? || vulnerability.detected?
        'detected'
      elsif vulnerability.resolved?
        'resolved'
      elsif vulnerability.dismissed? # fail-safe check for cases when dismissal feedback was lost or was not created
        'dismissed'
      else
        'confirmed'
      end
    end

    def token_status
      finding_token_status&.status_before_type_cast || ::Security::TokenStatus::UNKNOWN
    end

    def source_code?
      source_code.present?
    end

    def policy_comparison_uuid
      context_unaware_uuid || uuid
    end

    def vulnerable_code(lines: vulnerable_lines)
      strong_memoize_with(:vulnerable_code, lines) do
        source_code.lines[lines]&.join
      end
    end

    def self.related_dismissal_feedback
      Feedback.where('vulnerability_occurrences.uuid = vulnerability_feedback.finding_uuid')
              .for_dismissal
    end
    private_class_method :related_dismissal_feedback

    def self.dismissed
      where('EXISTS (?)', related_dismissal_feedback.select(1))
    end

    def feedback(feedback_type:)
      load_feedback.find { |f| f.feedback_type == feedback_type }
    end

    def load_feedback
      BatchLoader.for(uuid).batch do |uuids, loader|
        finding_feedbacks = Vulnerabilities::Feedback.all_preloaded.where(finding_uuid: uuids.uniq)

        uuids.each do |finding_uuid|
          loader.call(
            finding_uuid,
            finding_feedbacks.select { |f| finding_uuid == f.finding_uuid }
          )
        end
      end
    end

    def dismissal_feedback
      feedback(feedback_type: 'dismissal')
    end

    def issue_feedback
      related_issues = vulnerability&.related_issues
      related_issues.blank? ? feedback(feedback_type: 'issue') : Vulnerabilities::Feedback.find_by(issue: related_issues.first.id)
    end

    def merge_request_feedback
      feedback(feedback_type: 'merge_request')
    end

    def metadata
      strong_memoize(:metadata) do
        data = Gitlab::Json.parse(raw_metadata)

        data = {} unless data.is_a?(Hash)

        data
      rescue JSON::ParserError
        {}
      end
    end

    def description
      super.presence || metadata['description']
    end

    def solution
      super.presence || metadata['solution'] || remediations&.first&.dig('summary')
    end

    def location
      super.presence || metadata.fetch('location', {})
    end

    def file
      location['file']
    end

    def image
      location['image']
    end

    def links
      return metadata.fetch('links', []) if finding_links.load.empty?

      finding_links.as_json(only: [:name, :url])
    end

    def remediations
      return metadata['remediations'] unless super.present?

      super.as_json(only: [:summary], methods: [:diff])
    end

    def token_type
      return unless metadata['identifiers']

      rule_identifier(::Security::SecretDetection::RuleIdentifiers::GSS_TYPE) ||
        rule_identifier(::Security::SecretDetection::RuleIdentifiers::GITLEAKS_TYPE)
    end

    def token_value
      metadata['raw_source_code_extract']
    end

    def identifier_types
      Array.wrap(metadata['identifiers']).filter_map { |identifier| identifier['type'] if identifier.is_a?(Hash) }
    end

    def secret_redacted?
      return false unless secret_detection?

      vulnerability&.representation_information&.removed_from_code == true
    end

    REDACTED_PLACEHOLDER = '[redacted]'

    # The commit SHA is treated as a secret git ref. It can surface in several
    # places (location.commit, the details blob, and free text like the
    # description), so expose it here for callers that redact those surfaces.
    def redacted_commit_sha
      sha = location&.dig('commit', 'sha').presence
      sha unless sha == SECRET_DETECTION_DEFAULT_COMMIT_SHA
    end

    # Description text embeds the commit SHA for secret detection findings
    # (e.g. "... found in commit <sha>."), so strip it once redacted. Guarded so
    # serializers/exporters can call it unconditionally on any finding.
    def redacted_description
      return description unless secret_redacted?

      scrub_commit_sha(description)
    end

    # Returns the finding as a hash with the secret value and git ref redacted.
    # The secret lives inside the `raw_metadata` JSON (`raw_source_code_extract`),
    # not as a top-level attribute, so it must be scrubbed there. The git ref
    # also surfaces in `details`, `description` and inside `raw_metadata`. This
    # is the redacted form, so it scrubs unconditionally.
    def redacted_as_json
      as_json.tap do |hash|
        sanitized_metadata = metadata.except('raw_source_code_extract')
        if sanitized_metadata['location'].is_a?(Hash)
          sanitized_metadata['location'] = sanitized_metadata['location'].except('commit')
        end

        hash['raw_metadata'] = scrub_commit_sha(Gitlab::Json.dump(sanitized_metadata))
        hash['details'] = {}
        hash['location'] = hash['location'].except('commit') if hash['location'].is_a?(Hash)
        hash['description'] = scrub_commit_sha(hash['description'])
      end
    end

    def scrub_commit_sha(text)
      sha = redacted_commit_sha
      sha && text.is_a?(String) ? text.gsub(sha, REDACTED_PLACEHOLDER) : text
    end

    def cve_enrichment
      return unless cve_enrichments.load.any?

      cve_enrichments.first
    end
    strong_memoize_attr :cve_enrichment

    def build_evidence_request(data)
      return if data.nil?

      {
        headers: data.fetch('headers', []).map do |request_header|
          {
            name: request_header['name'],
            value: request_header['value']
          }
        end,
        method: data['method'],
        url: data['url'],
        body: data['body']
      }
    end

    def build_evidence_response(data)
      return if data.nil?

      {
        headers: data.fetch('headers', []).map do |header_data|
          {
            name: header_data['name'],
            value: header_data['value']
          }
        end,
        status_code: data['status_code'],
        reason_phrase: data['reason_phrase'],
        body: data['body']
      }
    end

    def build_evidence_supporting_messages(data)
      return [] if data.nil?

      data.map do |message|
        {
          name: message['name'],
          request: build_evidence_request(message['request']),
          response: build_evidence_response(message['response'])
        }
      end
    end

    def build_evidence_source(data)
      return if data.nil?

      {
        id: data['id'],
        name: data['name'],
        url: data['url']
      }
    end

    def evidence
      evidence_data = finding_evidence.present? ? finding_evidence.data : metadata['evidence']

      return if evidence_data.nil?

      {
        summary: evidence_data&.dig('summary'),
        request: build_evidence_request(evidence_data&.dig('request')),
        response: build_evidence_response(evidence_data&.dig('response')),
        source: build_evidence_source(evidence_data&.dig('source')),
        supporting_messages: build_evidence_supporting_messages(evidence_data&.dig('supporting_messages'))
      }
    end

    def cve_value
      identifiers.find(&:cve?)&.name
    end

    def cwe_value
      identifiers.find(&:cwe?)&.name
    end

    def cve_or_cwe
      identifiers.find(&:cve?) || identifiers.find(&:cwe?)
    end

    def other_identifier_values
      identifiers.select(&:other?).map(&:name)
    end

    def assets
      metadata.fetch('assets', []).map do |asset_data|
        {
          name: asset_data['name'],
          type: asset_data['type'],
          url: asset_data['url']
        }
      end
    end

    def risk_score
      finding_risk_score&.risk_score || 0.0
    end

    alias_method :==, :eql?

    def eql?(other)
      return false unless other.is_a?(self.class)
      # Mirrors the guard in #hash so comparing findings mid-preload never loads identifiers for either side.
      return super if compares_by_identity? || other.compares_by_identity?

      unless other.report_type == report_type && other.primary_identifier_fingerprint == primary_identifier_fingerprint
        return false
      end

      if project.licensed_feature_available?(:vulnerability_finding_signatures)
        matches_signatures(other.signatures, other.uuid)
      else
        other.location_fingerprint == location_fingerprint
      end
    end

    # Array.difference (-) method uses hash and eql? methods to do comparison
    # Note: Removing this method was investigated, but it is still being used in production.
    #       See https://gitlab.com/gitlab-org/gitlab/-/work_items/576423#note_3248222352 for more details
    def hash
      # This is causing N+1 queries whenever we are calling findings, ActiveRecord uses #hash method to make sure the
      # array with findings is uniq before preloading. This method is used only in Gitlab::Ci::Reports::Security::VulnerabilityReportsComparer
      # where we are normalizing security report findings into instances of Vulnerabilities::Finding, this is why we are using original implementation
      # when Finding is persisted and identifiers are not preloaded.
      return super if compares_by_identity?

      [report_type, location_fingerprint, primary_identifier_fingerprint].hash
    end

    def self.pluck_uuids
      pluck(:uuid)
    end

    def self.pluck_vulnerability_ids
      pluck(:vulnerability_id)
    end

    def self.pluck_with_limit(size, *columns)
      limit(size).pluck(*columns)
    end

    def pipeline_branch
      last_finding_pipeline&.sha || project.default_branch
    end

    def latest_flag
      return vulnerability_flags.max_by(&:updated_at) if vulnerability_flags.loaded?

      vulnerability_flags.latest.first
    end

    def false_positive?
      vulnerability_flags.any?(&:false_positive?)
    end

    def first_finding_pipeline
      initial_finding_pipeline
    end

    def last_finding_pipeline
      latest_finding_pipeline
    end

    def vulnerable_lines
      # -1 is a magic number here meaning an explicit value
      # for start_line or end_line was not provided.  If neither
      # were provided we return the entire file contents.
      return (0..-1) if (start_line < 0) && (end_line < 0)

      range_start = [start_line, 0].max
      range_end = [end_line, range_start].max

      (range_start..range_end)
    end

    def start_line
      location["start_line"].to_i - 1
    end

    def end_line
      location["end_line"].to_i - 1
    end

    def source_code
      return "" unless file.present?

      blob = project.repository.blob_at(pipeline_branch, file)
      blob.present? ? blob.data : ""
    end
    strong_memoize_attr :source_code

    def identifier_names
      identifiers.pluck(:name)
    end

    def ai_explanation_available?
      AI_ALLOWED_REPORT_TYPES.include?(report_type)
    end

    def ai_resolution_available?
      AI_ALLOWED_REPORT_TYPES.include?(report_type)
    end

    def ai_resolution_enabled?
      ai_resolution_available? && ai_resolution_supported_cwe?
    end

    def ai_resolution_supported_cwe?
      ::Feature.enabled?(:ignore_supported_cwe_list_check, project) ||
        HIGH_CONFIDENCE_AI_RESOLUTION_CWES.include?(cwe_value&.upcase)
    end

    def latest_detection_transition
      detection_transitions.last
    end

    def eligible_for_resolution_workflow?
      sast_fp_detection_workflow_exists?
    end

    def resolution_workflow_enabled?
      project.duo_sast_vr_workflow_enabled ||
        ::Vulnerabilities::AiTriage::Eligibility.enabled?(project, :sast_vulnerability_resolution)
    end

    private

    def rule_identifier(type)
      metadata['identifiers'].find { |identifier| identifier['type'] == type }&.dig('value')
    end

    def sanitize_details
      return if details.blank?

      self.details = details.transform_values do |detail|
        detail.is_a?(Hash) ? sanitize_detail(detail.with_indifferent_access) : detail
      end
    end

    protected

    def primary_identifier_fingerprint
      identifiers.first&.fingerprint
    end

    # Persisted findings with unloaded identifiers keep ActiveRecord's id-based #hash and #eql? so neither loads them.
    def compares_by_identity?
      persisted? && !identifiers.loaded?
    end

    def sast_fp_detection_workflow_exists?
      triggered_workflows.exists?(workflow_name: ::Vulnerabilities::TriggeredWorkflow::WORKFLOW_NAMES[:sast_fp_detection])
    end
  end
end

Vulnerabilities::Finding.prepend_mod

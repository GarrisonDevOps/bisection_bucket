# frozen_string_literal: true

module Vulnerabilities
  class Read < ::SecApplicationRecord
    extend EnforceVulnerabilityReadDbTriggerFf
    extend ::Gitlab::Utils::Override
    include ::Namespaces::Traversal::Traversable
    include VulnerabilityScopes
    include UnnestedInFilters::Dsl
    include FromUnion
    include ::Gitlab::SQL::Pattern
    include ::Elastic::ApplicationVersionedSearch

    declarative_enum DismissalReasonEnum

    # Included after scopes and relationships to avoid the warning
    include BulkInsertSafe

    SEVERITY_COUNT_LIMIT = 1001
    OWASP_TOP_10_DEFAULT = -1

    ELASTICSEARCH_TRACKED_FIELDS = ::Search::Elastic::References::Vulnerability::DIRECT_FIELDS +
      ::Search::Elastic::References::Vulnerability::DIRECT_TYPECAST_FIELDS + %w[traversal_ids]

    self.table_name = "vulnerability_reads"
    self.primary_key = :vulnerability_id

    delegate :group_name, :title, :created_at, :project_name, :finding_scanner_name, :finding_description, :cve_value, :cwe_value, :location, :notes_summary, :full_path, to: :vulnerability, allow_nil: true
    delegate :other_identifier_values, :cvss_vectors_with_vendor, to: :vulnerability, allow_nil: true
    delegate :dismissed?, to: :vulnerability
    delegate :context_name, to: :tracked_context, allow_nil: true

    belongs_to :vulnerability, inverse_of: :vulnerability_read
    belongs_to :project
    belongs_to :scanner, class_name: 'Vulnerabilities::Scanner'
    belongs_to :vulnerability_occurrence, optional: true, class_name: 'Vulnerabilities::Finding'
    belongs_to :tracked_context, class_name: 'Security::ProjectTrackedContext', optional: true,
      foreign_key: :security_project_tracked_context_id, inverse_of: :vulnerability_reads

    validates :vulnerability_id, uniqueness: true, presence: true
    validates :project_id, presence: true
    validates :scanner_id, presence: true
    validates :report_type, presence: true
    validates :severity, presence: true
    validates :state, presence: true
    validates :uuid, presence: true

    validates :location_image, length: { maximum: 2048 }
    validates :has_issues, inclusion: { in: [true, false], message: N_('must be a boolean value') }
    validates :has_merge_request, inclusion: { in: [true, false], message: N_('must be a boolean value') }
    validates :resolved_on_default_branch, inclusion: { in: [true, false], message: N_('must be a boolean value') }
    validates :has_remediations, inclusion: { in: [true, false], message: N_('must be a boolean value') }

    enum :state, ::Enums::Vulnerability.vulnerability_states
    enum :report_type, ::Enums::Vulnerability.report_types
    enum :severity, ::Enums::Vulnerability.severity_levels, prefix: :severity
    enum :owasp_top_10, ::Enums::Vulnerability.owasp_top_10.merge('undefined' => OWASP_TOP_10_DEFAULT)

    after_initialize :set_default_values, if: :new_record?

    scope :by_uuid, ->(uuids) { where(uuid: uuids) }
    scope :by_vulnerabilities, ->(vulnerabilities) { where(vulnerability: vulnerabilities) }
    scope :excluding_vulnerabilities, ->(vulnerabilities) { where.not(vulnerability: vulnerabilities) }

    class << self
      alias_method :by_vulnerability, :by_vulnerabilities
    end

    scope :order_severity_asc, -> { reorder(severity: :asc, vulnerability_id: :desc) }
    scope :order_severity_desc, -> { reorder(severity: :desc, vulnerability_id: :desc) }
    scope :order_detected_at_asc, -> { reorder(vulnerability_id: :asc) }
    scope :order_detected_at_desc, -> { reorder(vulnerability_id: :desc) }

    scope :order_severity_asc_traversal_ids_asc, -> { reorder(severity: :asc, traversal_ids: :asc, vulnerability_id: :asc) }
    scope :order_severity_desc_traversal_ids_desc, -> { reorder(severity: :desc, traversal_ids: :desc, vulnerability_id: :desc) }

    scope :in_parent_group_after_and_including, ->(vulnerability_read) do
      where(arel_grouping_by_traversal_ids_and_vulnerability_id.gteq(vulnerability_read.arel_grouping_by_traversal_ids_and_id))
    end
    scope :in_parent_group_before_and_including, ->(vulnerability_read) do
      where(arel_grouping_by_traversal_ids_and_vulnerability_id.lteq(vulnerability_read.arel_grouping_by_traversal_ids_and_id))
    end
    scope :by_group, ->(group) { within(group.traversal_ids) }
    scope :unarchived, -> { where(archived: false) }
    scope :with_archived_other_than, ->(archived) { where.not(archived: archived) }
    scope :order_traversal_ids_asc, -> do
      reorder(Gitlab::Pagination::Keyset::Order.build([
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'traversal_ids',
          order_expression: arel_table[:traversal_ids].asc,
          nullable: :not_nullable
        ),
        Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'vulnerability_id',
          order_expression: arel_table[:vulnerability_id].asc
        )
      ]))
    end
    scope :by_projects, ->(values) { where(project_id: values) }
    scope :by_scanner, ->(scanner) { where(scanner: scanner) }
    scope :by_scanner_ids, ->(scanner_ids) { where(scanner_id: scanner_ids) }
    scope :by_tracked_context, ->(tracked_context) { where(tracked_context: tracked_context) }
    scope :grouped_by_severity, -> { reorder(severity: :desc).group(:severity) }
    scope :with_report_types, ->(report_types) { where(report_type: report_types) }
    scope :with_severities, ->(severities) { where(severity: severities) }
    scope :with_states, ->(states) { where(state: states) }
    scope :with_due_date, ->(after_finding_id: 0) do
      where(vulnerability_occurrence_id: Vulnerabilities::FindingDueDate
        .where('vulnerability_occurrence_id > ?', after_finding_id).select(:vulnerability_occurrence_id))
    end
    scope :with_owasp_top_10, ->(owasp_top_10) { where(owasp_top_10: owasp_top_10) }
    scope :with_identifier_name, ->(name) do
      return none if name.nil?

      where("EXISTS (
        SELECT 1
        FROM unnest(vulnerability_reads.identifier_names) AS idt_names
        WHERE idt_names ILIKE ?
      )", sanitize_sql_like(name))
    end
    scope :with_container_image, ->(images) { where(location_image: images) }
    scope :with_container_image_starting_with, ->(image) { where(arel_table[:location_image].matches("#{sanitize_sql_like(image)}%")) }
    scope :with_cluster_agent_ids, ->(agent_ids) { where(cluster_agent_id: agent_ids) }
    scope :with_resolution, ->(has_resolution = true) { where(resolved_on_default_branch: has_resolution) }
    scope :with_ai_resolution, ->(resolution = true) { where(has_vulnerability_resolution: resolution) }
    scope :with_issues, ->(has_issues = true) { where(has_issues: has_issues) }
    scope :with_merge_request, ->(has_merge_request = true) { where(has_merge_request: has_merge_request) }
    scope :with_remediations, ->(has_remediations = true) { where(has_remediations: has_remediations) }
    scope :with_ai_created_merge_request, -> do
      where(vulnerability_id: ::Vulnerabilities::MergeRequestLink.created_by_ai_workflow.select(:vulnerability_id))
    end
    scope :created_between, ->(from, to) do
      joins(:vulnerability).merge(
        ::Vulnerability.created_in_time_range(from: from.beginning_of_day, to: to.end_of_day)
      )
    end
    scope :with_scanner_external_ids,
      ->(scanner_external_ids) {
        joins(:scanner).merge(::Vulnerabilities::Scanner.with_external_id(scanner_external_ids))
      }
    scope :with_findings_scanner_and_identifiers,
      -> {
        includes(vulnerability: { findings: [:scanner, :identifiers, { finding_identifiers: :identifier }] })
      }
    scope :preload_indexing_data, -> {
      preload(
        :scanner,
        :vulnerability_occurrence,
        :vulnerability,
        { project: :namespace }
      )
    }
    scope :resolved_on_default_branch, -> { where('resolved_on_default_branch IS TRUE') }
    scope :with_dismissal_reason, ->(dismissal_reason) { where(dismissal_reason: dismissal_reason) }
    scope :with_export_entities, ->(preload_notes: true) do
      vulnerability_associations = { project: [:route], findings: [:scanner, :identifiers] }
      vulnerability_associations[:notes] = [:updated_by, :author] if preload_notes

      preload(:tracked_context, vulnerability: [:group, vulnerability_associations])
    end

    scope :as_vulnerabilities, -> do
      preload(vulnerability: { project: [:route] }).current_scope.tap do |relation|
        relation.define_singleton_method(:records) do
          super().map(&:vulnerability)
        end
      end
    end

    scope :by_group_using_nested_loop, ->(group) do
      where(traversal_ids: all_vulnerable_traversal_ids_for(group))
    end

    scope :with_limit, ->(maximum) { limit(maximum) }
    scope :order_id_desc, -> { reorder(arel_table[:vulnerability_id].desc) }

    scope :autocomplete_search, ->(query) do
      return self if query.blank?

      id_as_text = Arel::Nodes::NamedFunction.new('CAST', [arel_table[:vulnerability_id].as('TEXT')])

      joins(:vulnerability)
        .select('vulnerability_reads.*, vulnerabilities.title')
        .fuzzy_search(query, [Vulnerability.arel_table[:title]])
        .or(where(id_as_text.matches("%#{sanitize_sql_like(query.squish)}%")))
    end

    scope :by_ids_desc, ->(ids) do
      by_vulnerability(ids).order_id_desc
    end

    def self.with_true_positive_ai_flag
      flags = ::Vulnerabilities::Flag.arel_table
      latest_flag_status =
        flags.project(flags[:status])
          .where(flags[:vulnerability_occurrence_id].eq(arel_table[:vulnerability_occurrence_id]))
          .where(flags[:flag_type].eq(::Vulnerabilities::Flag.flag_types[:false_positive]))
          .order(flags[:id].desc)
          .take(1)

      where(Arel::Nodes::Grouping.new(latest_flag_status).eq(::Vulnerabilities::Flag.statuses[:detected_as_not_fp]))
    end

    def self.es_type
      ::Search::Elastic::References::Vulnerability::DOC_TYPE
    end

    def self.arel_grouping_by_traversal_ids_and_vulnerability_id
      arel_table.grouping([arel_table['traversal_ids'], arel_table['vulnerability_id']])
    end

    def self.all_vulnerable_traversal_ids_for(group)
      by_group(group).unarchived.loose_index_scan(column: :traversal_ids)
    end

    def self.count_by_severity
      grouped_by_severity.count
    end

    def self.capped_count_by_severity
      # Return early when called by `Vulnerabilities::Read.none`.
      return {} if current_scope&.null_relation?

      # Handles case when called directly `Vulnerabilities::Read.capped_count_by_severity`.
      if current_scope.nil?
        severities_to_iterate = severities.keys
        local_scope = self
      else
        severities_to_iterate = Array(current_scope.where_values_hash['severity'].presence || severities.keys)
        local_scope = current_scope.unscope(where: :severity)
      end

      array_severities_limit = severities_to_iterate.map do |severity|
        local_scope.with_severities(severity).select(:id, :severity).limit(SEVERITY_COUNT_LIMIT)
      end

      unscoped.from_union(array_severities_limit).count_by_severity
    end

    def self.order_by(method)
      case method.to_s
      when 'severity_asc' then order_severity_asc
      when 'detected_desc' then order_detected_at_desc
      when 'detected_asc' then order_detected_at_asc
      else
        order_severity_desc
      end
    end

    def self.order_by_params_and_traversal_ids(method)
      case method.to_s
      when 'severity_asc' then order_severity_asc_traversal_ids_asc
      when 'detected_desc' then order_detected_at_desc
      when 'detected_asc' then order_detected_at_asc
      else order_severity_desc_traversal_ids_desc
      end
    end

    def self.container_images
      # This method should be used only with pagination. When used without a specific limit, it might try to process an
      # unreasonable amount of records leading to a statement timeout.

      # We are enforcing keyset order here to make sure `primary_key` will not be automatically applied when returning
      # `ordered_items` from Gitlab::Graphql::Pagination::Keyset::Connection in GraphQL API. `distinct` option must be
      # set to true in `Gitlab::Pagination::Keyset::ColumnOrderDefinition` to return the collection in proper order.

      keyset_order = Gitlab::Pagination::Keyset::Order.build(
        [
          Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
            attribute_name: :location_image,
            column_expression: arel_table[:location_image],
            order_expression: arel_table[:location_image].asc
          )
        ])

      where(report_type: [:container_scanning, :cluster_image_scanning])
        .where.not(location_image: nil)
        .reorder(keyset_order)
        .select(:location_image)
        .distinct
    end

    def self.fetch_uuids
      pluck(:uuid)
    end

    def self.generate_es_parent(project)
      "group_#{project.namespace.root_ancestor.id}"
    end

    def arel_grouping_by_traversal_ids_and_id
      self.class.arel_table.grouping([database_serialized_traversal_ids, id])
    end

    def es_parent
      self.class.generate_es_parent(project)
    end

    def elastic_reference
      vulnerability_ref = ::Search::Elastic::References::Vulnerability.serialize(self)

      if dual_write_to_es?
        vulnerability_read_ref = ::Search::Elastic::References::Vulnerabilities::Read.serialize(self)

        return [
          vulnerability_ref,
          vulnerability_read_ref
        ]
      end

      vulnerability_ref
    end

    def dual_write_to_es?
      Feature.enabled?(:vulnerability_read_es_dual_write, project) &&
        ::Elastic::DataMigrationService.migration_has_finished?(:create_vulnerability_reads_index) # rubocop:disable CodeReuse/ServiceClass -- Same pattern as ApplicationVersionedSearch#associations_needing_elasticsearch_update
    end

    # NOTE:
    # 1. For On-premise, post MVC. We may have to honour the setting of skipping indexing for selected projects. Tracked in https://gitlab.com/gitlab-org/gitlab/-/issues/525484
    override :use_elasticsearch?
    def use_elasticsearch?
      ::Search::Elastic::VulnerabilityIndexHelper.indexing_allowed?
    end

    override :maintain_elasticsearch_update
    def maintain_elasticsearch_update(updated_attributes: previous_changes.keys)
      super if update_elasticsearch?
    end

    private

    def update_elasticsearch?
      changed_fields = previous_changes.keys
      changed_fields && (changed_fields & ELASTICSEARCH_TRACKED_FIELDS).any?
    end

    def database_serialized_traversal_ids
      self.class.attribute_types['traversal_ids']
                .serialize(traversal_ids)
                .then { |serialized_array| self.class.connection.quote(serialized_array) }
                .then { |quoted_array| Arel::Nodes::SqlLiteral.new(quoted_array) }
    end

    def set_default_values
      self.owasp_top_10 ||= 'undefined'
    end
  end
end

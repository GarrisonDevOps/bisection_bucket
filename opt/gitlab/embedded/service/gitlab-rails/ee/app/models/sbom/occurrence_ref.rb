# frozen_string_literal: true

module Sbom
  class OccurrenceRef < ::SecApplicationRecord
    include Ci::Partitionable::AssociationFinder
    include ::Elastic::ApplicationVersionedSearch

    self.table_name = 'sbom_occurrence_refs'

    has_many :occurrences_vulnerabilities,
      class_name: 'Sbom::OccurrencesVulnerability',
      foreign_key: :sbom_occurrence_ref_id,
      inverse_of: :occurrence_ref

    belongs_to :project,
      inverse_of: :sbom_occurrence_refs

    belongs_to :occurrence,
      class_name: 'Sbom::Occurrence',
      foreign_key: :sbom_occurrence_id,
      inverse_of: :occurrence_refs

    belongs_to :tracked_context,
      class_name: 'Security::ProjectTrackedContext',
      foreign_key: :security_project_tracked_context_id,
      inverse_of: :sbom_occurrence_refs

    belongs_to :pipeline,
      class_name: 'Ci::Pipeline',
      inverse_of: :sbom_occurrence_refs,
      optional: true
    partitionable_belongs_to_loader :pipeline

    enum :reachability, ::Enums::Sbom.reachability_types, suffix: true

    validates :commit_sha, presence: true, length: { maximum: 64 }
    validates :sbom_occurrence_id, presence: true
    validates :security_project_tracked_context_id, presence: true
    validates :project_id, presence: true

    scope :by_occurrence, ->(occurrence_id) { where(sbom_occurrence_id: occurrence_id) }
    scope :by_tracked_context, ->(context_id) { where(security_project_tracked_context_id: context_id) }
    scope :by_project, ->(project_id) { where(project_id: project_id) }
    scope :preload_indexing_data, -> {
      preload(
        :tracked_context,
        { project: :namespace },
        { occurrence: [:source, :component, :component_version, :project] }
      )
    }

    # Returns { sbom_occurrence_id => reachability } over the refs a dependency list request is
    # scoped to. Unscoped requests prefer the default branch, like the Elasticsearch-backed list,
    # and fall back to any ref for occurrences that are only tracked elsewhere. Occurrences without
    # refs are absent, so callers fall back to the occurrence value.
    def self.reachability_by_occurrence(occurrence_ids, tracked_context_ids: nil, tracked_refs_scope: nil)
      refs = by_occurrence(occurrence_ids).joins(:tracked_context, :occurrence)

      if tracked_context_ids.present?
        refs = refs.by_tracked_context(tracked_context_ids)
      elsif tracked_refs_scope == :default_branches
        refs = refs.merge(::Security::ProjectTrackedContext.default_refs)
      end

      prefer_default = tracked_context_ids.blank? && tracked_refs_scope.nil?

      rows = refs.pluck(:sbom_occurrence_id, ::Sbom::Occurrence.ref_reachability, ::Security::ProjectTrackedContext.arel_table[:is_default]) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- bounded by the batch of occurrence ids

      rows.group_by(&:first).transform_values do |occurrence_rows|
        occurrence_rows = occurrence_rows.select(&:third).presence || occurrence_rows if prefer_default

        strongest_reachability(occurrence_rows.map { |row| ::Enums::Sbom.reachability_types.key(row.second) })
      end
    end

    def self.strongest_reachability(reachabilities)
      return ::Enums::Sbom::IN_USE.to_s if reachabilities.include?(::Enums::Sbom::IN_USE.to_s)
      return ::Enums::Sbom::NOT_FOUND.to_s if reachabilities.include?(::Enums::Sbom::NOT_FOUND.to_s)

      ::Enums::Sbom::UNKNOWN.to_s
    end

    def self.generate_es_parent(project)
      "group_#{project.namespace.root_ancestor.id}"
    end

    def es_parent
      self.class.generate_es_parent(project)
    end

    def elastic_reference
      ::Search::Elastic::References::Sbom::OccurrenceRef.serialize(self)
    end
  end
end

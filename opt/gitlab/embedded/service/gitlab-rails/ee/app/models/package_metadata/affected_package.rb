# frozen_string_literal: true

module PackageMetadata
  class AffectedPackage < ApplicationRecord
    include Gitlab::Utils::StrongMemoize
    include BulkInsertSafe

    belongs_to :advisory, class_name: 'PackageMetadata::Advisory', optional: false, foreign_key: :pm_advisory_id,
      inverse_of: :affected_packages

    enum :purl_type, ::Enums::Sbom.purl_types

    validates :purl_type, presence: true
    validates :package_name, presence: true, length: { maximum: 256 }
    validates :distro_version, length: { maximum: 256 }
    validates :solution, length: { maximum: 2048 }
    validates :affected_range, presence: true, length: { maximum: 1024 }
    validates :overridden_advisory_fields, json_schema: { filename: 'pm_affected_package_overridden_advisory_fields' }
    validates :fixed_versions, length: { maximum: 10 }
    validates :versions, json_schema: { filename: 'pm_affected_package_versions' }

    scope :for_occurrences, ->(occurrences) { with(occurrence_cte(occurrences)).from(occurrence_lateral_from) }

    scope :with_advisory, -> { includes(:advisory).distinct }

    def self.occurrence_cte(occurrences)
      occurrence_data = occurrences.map do |occ|
        [::Enums::Sbom.purl_types[occ.purl_type], occ.name]
      end

      Arel::Nodes::As.new(
        Hashie::Mash.new(
          name: Arel.sql('occurrences_cte(purl_type, name)')
        ), Arel::Nodes::Grouping.new(Arel::Nodes::ValuesList.new(occurrence_data))
      )
    end

    # LATERAL forces one index seek per occurrence. Without the OFFSET 0 fence the
    # planner flattens the subquery back into a join and may pick a primary key scan
    # for the `ORDER BY id LIMIT 1` probe that each_batch runs.
    def self.occurrence_lateral_from
      "occurrences_cte, LATERAL (SELECT * FROM #{quoted_table_name} " \
        "WHERE #{quoted_table_name}.purl_type = occurrences_cte.purl_type " \
        "AND #{quoted_table_name}.package_name = occurrences_cte.name OFFSET 0) #{quoted_table_name}"
    end

    def solution_text
      return solution if solution.present?

      # This is a Container Scanning affected package, check for presence of fixed_versions.
      explicit_fixed_version = fixed_versions.delete_if { |v| v == '*' }
      return 'Unfortunately, there is no solution available yet.' if explicit_fixed_version.empty?

      "Upgrade to version #{explicit_fixed_version.join(', ')} or above"
    end
  end
end

# frozen_string_literal: true

module Sbom
  class ComponentVersion < ::SecApplicationRecord
    belongs_to :component, optional: false
    has_many :occurrences, inverse_of: :component_version
    belongs_to :organization, class_name: 'Organizations::Organization'

    validates :version, presence: true, length: { maximum: 255 }

    scope :by_component_id_and_version, ->(component_id, version) do
      where(component_id: component_id, version: version)
    end

    scope :by_project, ->(project) { joins(:occurrences).merge(Occurrence.for_project(project)) }
    scope :by_component_id, ->(component_id) { where(component_id: component_id) }
    scope :by_component_name, ->(component_name) {
      joins(:occurrences).merge(Occurrence.by_component_name_collated(component_name))
    }

    scope :order_by_version, ->(verse = :asc) { order(version: verse) }

    def self.select_distinct(on:)
      select_values = column_names.map do |column|
        adapter_class.quote_table_name("#{table_name}.#{column}")
      end

      distinct_values = Array(on).map { |column| arel_table[column] }
      distinct_sql = Arel::Nodes::DistinctOn.new(distinct_values).to_sql

      select("#{distinct_sql} #{select_values.join(', ')}")
    end
  end
end

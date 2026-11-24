# frozen_string_literal: true

class Packages::BuildInfo < ApplicationRecord
  include Ci::Partitionable::AssociationFinder

  belongs_to :package, inverse_of: :build_infos
  belongs_to :pipeline, class_name: 'Ci::Pipeline'
  belongs_to :project
  partitionable_belongs_to_loader :pipeline

  scope :without_empty_pipelines, -> { where.not(pipeline_id: nil) }
  scope :order_by_pipeline_id, ->(direction) { order(pipeline_id: direction) }
  scope :with_pipeline_id_less_than, ->(pipeline_id) { where("#{table_name}.pipeline_id < ?", pipeline_id) }
  scope :with_pipeline_id_greater_than, ->(pipeline_id) { where("#{table_name}.pipeline_id > ?", pipeline_id) }

  # One index probe per package via LATERAL, so a package's full build history is never read.
  # The ids come from unnest, so the lookup does not read packages_packages again.
  def self.latest_per_package(package_ids)
    return {} if package_ids.empty?

    ids = Arel::Table.new(:package_ids)
    ids_source = Arel.sql(sanitize_sql_array(['unnest(ARRAY[?]::bigint[]) AS package_ids(id)', package_ids]))
    latest = where(arel_table[:package_id].eq(ids[:id])).order(id: :desc).limit(1)

    with_partition_aware_preload
      .from([ids_source, latest.arel.lateral.as(table_name)])
      .preload(pipeline: [:user, { project: { namespace: :route } }])
      .index_by(&:package_id)
  end

  def self.supported_keyset_orderings
    { id: [:desc] }
  end
end

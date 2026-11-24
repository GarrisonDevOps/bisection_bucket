# frozen_string_literal: true

class Analytics::DevopsAdoption::EnabledNamespace < ApplicationRecord
  self.table_name = 'analytics_devops_adoption_segments'

  belongs_to :namespace
  belongs_to :display_namespace, class_name: 'Namespace', optional: true

  has_many :snapshots, foreign_key: :namespace_id, primary_key: :namespace_id

  validates :namespace, uniqueness: { scope: :display_namespace_id }, presence: true
  validate :namespaces_within_organization_boundary

  scope :ordered_by_name, -> do
    order = ::Gitlab::Pagination::Keyset::Order.build(
      [
        ::Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'namespaces_name',
          order_expression: Namespace.arel_table[:name].asc,
          add_to_projections: true
        ),
        ::Gitlab::Pagination::Keyset::ColumnOrderDefinition.new(
          attribute_name: 'id',
          order_expression: arel_table[:id].desc
        )
      ])
    query = includes(:namespace).order(order)
    order.apply_cursor_conditions(query)
  end

  scope :for_display_namespaces, ->(namespaces) { where(display_namespace_id: namespaces) }
  scope :for_namespaces, ->(namespaces) { where(namespace_id: namespaces) }
  scope :for_parent, ->(namespace) { for_namespaces(namespace.self_and_descendants) }
  scope :pending_calculation, -> {
    subquery = Analytics::DevopsAdoption::Snapshot.finalized.for_month(1.month.before(Time.zone.now))
      .where(Analytics::DevopsAdoption::Snapshot.arel_table[:namespace_id].eq(arel_table[:namespace_id]))
      .arel.exists

    where.not(subquery)
  }

  ignore_column :last_recorded_at, remove_with: '14.2', remove_after: '2021-07-22'

  def latest_snapshot
    snapshots.by_end_time.first
  end

  private

  # An isolated organization is a data boundary; organizations that are not isolated keep sharing tables.
  def namespaces_within_organization_boundary
    return unless namespace && display_namespace
    return if namespace.organization_id == display_namespace.organization_id
    return if namespace.organization.not_isolated? && display_namespace.organization.not_isolated?

    errors.add(:base, _('Namespace must be in the same organization as the display namespace'))
  end
end

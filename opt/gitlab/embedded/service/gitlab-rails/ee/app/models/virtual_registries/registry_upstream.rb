# frozen_string_literal: true

module VirtualRegistries
  class RegistryUpstream < ApplicationRecord
    self.abstract_class = true

    belongs_to :group

    validates :upstream_id, uniqueness: { scope: :registry_id }, if: :upstream_id?
    validates :registry_id, uniqueness: { scope: [:position] }

    validates :group, top_level_group: true, presence: true
    validates :position,
      numericality: {
        only_integer: true,
        greater_than_or_equal_to: 1,
        less_than_or_equal_to: ->(record) { record.class::MAX_UPSTREAMS_COUNT }
      },
      presence: true

    before_validation :set_group, :set_position, on: :create

    def self.declarative_policy_class
      'VirtualRegistries::Policies::GroupPolicy'
    end

    def self.sync_higher_positions(registry_upstreams)
      subquery = registry_upstreams.select(:registry_id, :position)

      # The column must be table-qualified: the relation joins a subquery, so
      # Rails 8.1 aliases the updated table and a bare column name is ambiguous.
      joins("INNER JOIN (#{subquery.to_sql}) AS subquery ON #{table_name}.registry_id = subquery.registry_id")
        .where("#{table_name}.position > subquery.position")
        .update_all(position: arel_table[:position] - 1)
    end

    def self.registries_count_by_upstream_ids(upstream_ids)
      return {} if upstream_ids.blank?

      where(upstream_id: upstream_ids)
        .group(:upstream_id)
        .count
    end

    def sync_higher_positions
      return if position == self.class::MAX_UPSTREAMS_COUNT

      self.class
        .where(registry_id: registry_id, position: (position + 1)..)
        .update_all(position: Arel.sql('position - 1'))
    end

    def update_position(new_position)
      max = self.class::MAX_UPSTREAMS_COUNT

      errors.add(:position, :greater_than_or_equal_to, count: 1) if new_position < 1
      errors.add(:position, :less_than_or_equal_to, count: max) if new_position > max
      return false if errors.any?

      return true if position == new_position

      relation = self.class.where(registry_id:)

      capped_pos = [new_position, relation.maximum(:position)].min

      return true if position == capped_pos

      arel_id = self.class.arel_table[:id]
      arel_pos = self.class.arel_table[:position]

      case_clause = Arel::Nodes::Case.new.when(arel_id.eq(id)).then(capped_pos)

      case_clause = if capped_pos > position
                      case_clause.when(arel_pos.between((position + 1)..capped_pos)).then(arel_pos - 1)
                    else
                      case_clause.when(arel_pos.between(capped_pos..(position - 1))).then(arel_pos + 1)
                    end.else(arel_pos)

      relation.update_all(position: case_clause)
      true
    end

    private

    def set_group
      self.group ||= (registry || upstream).group
    end

    def set_position
      self.position = self.class.where(registry:, group:).maximum(:position).to_i + 1
    end
  end
end

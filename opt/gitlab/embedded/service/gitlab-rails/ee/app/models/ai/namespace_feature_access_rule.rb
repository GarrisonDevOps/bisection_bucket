# frozen_string_literal: true

module Ai
  class NamespaceFeatureAccessRule < ApplicationRecord
    include FeatureAccessRuleable

    self.table_name = 'ai_namespace_feature_access_rules'

    belongs_to :through_namespace,
      class_name: 'Namespace',
      optional: true,
      inverse_of: :ai_feature_rules_through_namespace

    belongs_to :root_namespace,
      class_name: 'Namespace',
      inverse_of: :ai_feature_rules

    validates :root_namespace_id, presence: true

    validates :accessible_entity,
      uniqueness: { scope: [:root_namespace_id], conditions: -> { where(through_namespace_id: nil) } },
      if: -> { through_namespace_id.nil? }

    validate :through_namespace_root_is_root_namespace

    def self.by_root_namespace_group_by_through_namespace(root_namespace)
      group_based_ids = joins(:through_namespace)
        .where(namespaces: { parent_id: root_namespace.id, type: 'Group' })
        .select(:id)
      default_ids = where(root_namespace: root_namespace, through_namespace_id: nil).select(:id)

      group_by_through_namespace(
        where(id: group_based_ids).or(where(id: default_ids))
      )
    end

    def self.group_by_through_namespace(scope = nil)
      (scope || all)
        .includes(:through_namespace)
        .order(Arel.sql('through_namespace_id NULLS FIRST'), :accessible_entity)
        .group_by(&:through_namespace_id)
    end

    scope :accessible_for_user, ->(user, accessible_entity, namespace) {
      group_based_ids = joins(
        "INNER JOIN members " \
          "ON members.source_id = ai_namespace_feature_access_rules.through_namespace_id " \
          "AND members.source_type = 'Namespace'"
      ).where(
        accessible_entity: accessible_entity,
        members: { user_id: user.id },
        ai_namespace_feature_access_rules: { root_namespace: namespace }
      ).select(:id)

      default_ids = where(
        accessible_entity: accessible_entity,
        through_namespace_id: nil,
        root_namespace: namespace
      ).select(:id)

      where(id: group_based_ids).or(where(id: default_ids))
    }

    scope :for_namespace, ->(namespace) {
      where(root_namespace: namespace)
    }

    private

    def through_namespace_root_is_root_namespace
      return if through_namespace.blank?
      return if root_namespace.blank?
      return if through_namespace.root_ancestor.id == root_namespace_id

      errors.add(:through_namespace, 'must belong to the same root namespace as the root_namespace')
    end
  end
end

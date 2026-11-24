# frozen_string_literal: true

module Ai
  class FeatureAccessRule < ApplicationRecord
    include FeatureAccessRuleable

    self.table_name = 'ai_instance_accessible_entity_rules'

    belongs_to :through_namespace,
      class_name: 'Namespace',
      optional: true,
      inverse_of: :accessible_ai_features_on_instance

    validates :accessible_entity,
      uniqueness: { conditions: -> { where(through_namespace_id: nil) } },
      if: -> { through_namespace_id.nil? }
    validate :through_namespace_is_group, if: -> { through_namespace_id.present? }

    # Direct memberships only, by design: a rule must not widen to descendant groups, so this
    # deliberately joins members rather than walking traversal_ids.
    scope :accessible_for_user, ->(user, accessible_entity) {
      group_based_ids = joins(
        "INNER JOIN members " \
          "ON members.source_id = ai_instance_accessible_entity_rules.through_namespace_id " \
          "AND members.source_type = 'Namespace'"
      ).where(accessible_entity: accessible_entity, members: { user_id: user.id }).select(:id)

      default_ids = where(accessible_entity: accessible_entity, through_namespace_id: nil).select(:id)

      where(id: group_based_ids).or(where(id: default_ids))
    }

    class << self
      # Memoized per request, because access checks for many projects or groups would each run it.
      #
      # @return [Boolean] whether any instance-level rule exists
      def exists_for_request?
        ::Gitlab::SafeRequestStore.fetch(:ai_feature_access_rules_exist) { exists? }
      end

      def duo_namespace_access_rules
        group_by_through_namespace all
      end

      # Groups rules by namespace id for the admin page and the REST entity. The namespace and its
      # route are preloaded so rendering full_path costs no query per group.
      #
      # @param scope [ActiveRecord::Relation<Ai::FeatureAccessRule>]
      # @return [Hash{Integer, nil => Array<Ai::FeatureAccessRule>}] default rules under the nil key
      def group_by_through_namespace(scope)
        scope
          .includes(through_namespace: :route)
          .order(Arel.sql('through_namespace_id NULLS FIRST'), :accessible_entity)
          .reject { |rule| dangling?(rule) }
          .group_by(&:through_namespace_id)
      end

      # Replaces every rule with the given set. Only the delete and the insert share a transaction, so
      # a rejected insert keeps the existing rules instead of leaving the table empty.
      #
      # @param values [Array<Hash>] `{ through_namespace: { id: Integer } or nil, features: Array<String> }`
      def duo_namespace_access_rules=(values)
        values = values.map(&:deep_symbolize_keys).reject(&:blank?)
        rules = build_rules(values)

        transaction do
          delete_all

          bulk_insert!(rules) if rules.any?
        end
      end

      private

      # The loose foreign key on through_namespace_id is cleaned up asynchronously, so a rule for a
      # just-deleted group lingers with no namespace and would otherwise render as the default rule.
      #
      # @param rule [Ai::FeatureAccessRule]
      # @return [Boolean]
      def dangling?(rule)
        rule.through_namespace_id.present? && rule.through_namespace.nil?
      end

      # Builds the unsaved rows for a save, with namespaces preloaded and duplicates rejected, before
      # the write transaction opens.
      #
      # @param values [Array<Hash>] see {.duo_namespace_access_rules=}
      # @return [Array<Ai::FeatureAccessRule>] unsaved rows
      def build_rules(values)
        timestamp = Time.current
        rules = values.flat_map do |rule|
          features = rule[:features].reject(&:blank?)
          next [] if features.blank?

          through_namespace_id = rule.dig(:through_namespace, :id).presence

          features.map do |access_entity|
            new(
              through_namespace_id: through_namespace_id,
              accessible_entity: access_entity,
              created_at: timestamp,
              updated_at: timestamp
            )
          end
        end

        preload_namespaces(rules)
        reject_duplicate!(rules)
        rules
      end

      # The group check reads through_namespace on every row during bulk_insert! validation, so the
      # batch is loaded in one query. Missing ids stay unassigned so the check rejects them.
      #
      # @param rules [Array<Ai::FeatureAccessRule>] unsaved rows
      # @return [void]
      def preload_namespaces(rules)
        ids = rules.filter_map(&:through_namespace_id).uniq
        return if ids.empty?

        namespaces = Namespace.id_in(ids).index_by(&:id)
        rules.each do |rule|
          namespace = namespaces[rule.through_namespace_id]
          rule.through_namespace = namespace if namespace
        end

        nil
      end

      # bulk_insert! validates each record against the table, not against the rest of the batch, so a
      # repeated namespace would only fail at the unique index and surface as a 500 instead of a 400.
      #
      # @param rules [Array<Ai::FeatureAccessRule>] unsaved rows
      # @raise [ActiveRecord::RecordInvalid] on the first repeated namespace and feature pair
      # @return [void]
      def reject_duplicate!(rules)
        duplicate = rules
          .group_by { |rule| [rule.through_namespace_id, rule.accessible_entity] }
          .each_value.find { |group| group.size > 1 }&.first
        return unless duplicate

        duplicate.errors.add(:accessible_entity, _('is listed more than once for the same namespace'))
        raise ActiveRecord::RecordInvalid, duplicate
      end
    end

    private

    # Rules match group memberships, so a user or project namespace can never grant access.
    #
    # @return [void]
    def through_namespace_is_group
      return if through_namespace&.group_namespace?

      errors.add(:through_namespace, _('must be a group'))
      nil
    end
  end
end

# frozen_string_literal: true

module Analytics
  module CycleAnalytics
    class Stage < ApplicationRecord
      include Analytics::CycleAnalytics::Stageable
      include Analytics::CycleAnalytics::Parentable

      MAX_STAGES_PER_VALUE_STREAM = 15
      MAX_STAGES_PER_HIERARCHY = 750

      self.table_name = :analytics_cycle_analytics_group_stages

      validates :name, uniqueness: { scope: [:group_id, :group_value_stream_id] }
      validate :max_stages_count, on: :create
      validate :max_stages_per_hierarchy, on: :create
      validate :validate_default_stage_name

      belongs_to :value_stream, class_name: 'Analytics::CycleAnalytics::ValueStream',
        foreign_key: :group_value_stream_id, inverse_of: :stages
      has_one :stage_aggregation, class_name: 'Analytics::CycleAnalytics::StageAggregation', inverse_of: :stage

      alias_method :parent, :namespace
      alias_method :parent=, :namespace=

      alias_attribute :parent_id, :group_id
      alias_attribute :value_stream_id, :group_value_stream_id

      after_create :ensure_aggregation_record_presence!

      def self.distinct_stages_within_hierarchy(namespace)
        within_hierarchy(namespace)
          .with_preloaded_labels
          .select("DISTINCT ON(stage_event_hash_id) #{quoted_table_name}.*")
      end

      def self.within_hierarchy(namespace)
        # Looking up the whole hierarchy including all kinds (type) of Namespace records.
        # We're doing a custom traversal_ids query because:
        # - The traversal_ids based `self_and_descendants` doesn't include the ProjectNamespace records.
        # - The default recursive lookup also excludes the ProjectNamespace records.
        #
        # Related issue: https://gitlab.com/gitlab-org/gitlab/-/issues/386124
        all_namespace_ids =
          Namespace
          .select(Arel.sql('namespaces.traversal_ids[array_length(namespaces.traversal_ids, 1)]').as('id'))
          .where("traversal_ids @> ('{?}')", namespace.id)

        where(parent_id: all_namespace_ids)
      end

      def to_global_id
        return super if persisted?

        # Returns default name as the id for built in stages at the FOSS level
        name
      end

      private

      def max_stages_count
        return unless value_stream
        return unless value_stream.stages.count >= MAX_STAGES_PER_VALUE_STREAM

        errors.add(:value_stream, _('Maximum number of stages per value stream exceeded'))
      end

      def max_stages_per_hierarchy
        return unless new_record? && namespace

        root_namespace = namespace.root_ancestor
        return unless Feature.enabled?(:vsa_hierarchy_stage_limit, root_namespace)

        persisted_count = self.class.within_hierarchy(root_namespace).count
        return if persisted_count + pending_stages_count <= MAX_STAGES_PER_HIERARCHY

        errors.add(:namespace, _('Maximum number of stages per top-level namespace exceeded'))
      end

      # Stages submitted together through `stages_attributes` all validate before any is inserted or
      # destroyed, so unsaved siblings are added to the count and siblings marked for destruction are subtracted.
      def pending_stages_count
        return 1 unless value_stream

        siblings = value_stream.stages.target
        [siblings.count(&:new_record?), 1].max - siblings.count(&:marked_for_destruction?)
      end

      def validate_default_stage_name
        return if name.blank?
        return if custom
        return if Gitlab::Analytics::CycleAnalytics::DefaultStages.find_by_name(name.downcase)

        names = Gitlab::Analytics::CycleAnalytics::DefaultStages.names.join(', ')
        message = format(_('Invalid name %{input} was given for this default stage, allowed names: %{names}'),
          input: name.downcase, names: names)
        errors.add(:name, message)
      end

      def ensure_aggregation_record_presence!
        stage_aggregation || create_stage_aggregation!(enabled: true, namespace: namespace)
      end
    end
  end
end

# frozen_string_literal: true

module WorkItems
  class AgentPlan < ApplicationRecord
    include CacheMarkdownField

    self.table_name = 'work_item_agent_plans'

    CONTENT_LENGTH_MAX = 128.kilobytes

    ignore_columns :file_store, remove_with: '19.7', remove_after: '2026-11-14'

    cache_markdown_field :content, storage: :external, issuable_reference_expansion_enabled: true
    cache_markdown_field :readiness_score_feedback, storage: :external, issuable_reference_expansion_enabled: true
    mount_external_storage ::WorkItems::AgentPlanContentUploader

    belongs_to :work_item, inverse_of: :agent_plan
    belongs_to :namespace

    validates :namespace, presence: true
    validates :work_item, presence: true
    validates :content, length: { maximum: CONTENT_LENGTH_MAX }
    validates :readiness_score, numericality: { only_integer: true, in: 0..100 }, allow_nil: true
    validates :readiness_score_feedback, length: { maximum: CONTENT_LENGTH_MAX }
    validate :ai_planning_enabled_cannot_be_unset, if: :ai_planning_enabled_changed?

    before_validation :set_namespace

    def has_content?
      external_payload_stored?(:content)
    end

    private

    def set_namespace
      return if work_item.nil?
      return if work_item.namespace == namespace

      self.namespace = work_item.namespace
    end

    def ai_planning_enabled_cannot_be_unset
      return unless ai_planning_enabled_was && !ai_planning_enabled

      errors.add(:base, _('AI planning cannot be disabled once it has been enabled.'))
    end
  end
end

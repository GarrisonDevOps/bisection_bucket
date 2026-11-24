# frozen_string_literal: true

module WorkItems
  class Decision < ApplicationRecord
    self.table_name = 'work_item_decisions'

    TITLE_LENGTH_MAX = 255
    SOURCE_LINK_LENGTH_MAX = 2048
    MAX_OPTIONS_PER_DECISION = 5
    MAX_OPTIONS_WITH_WRITE_IN = MAX_OPTIONS_PER_DECISION + 1

    # Soft limits, deliberately below the DB check constraints (3000) so they
    # can be raised without a migration
    DESCRIPTION_LENGTH_MAX = 1000
    RESOLUTION_RATIONALE_LENGTH_MAX = 800

    alias_attribute :question, :title

    belongs_to :work_item, inverse_of: :decisions
    belongs_to :namespace
    belongs_to :author, class_name: 'User'
    belongs_to :resolved_by, class_name: 'User', optional: true
    belongs_to :resolving_note, class_name: 'Note', optional: true
    belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow', optional: true
    belongs_to :description_version, optional: true

    has_many :options,
      -> { order(:id) },
      class_name: 'WorkItems::DecisionOption',
      foreign_key: :work_item_decision_id,
      inverse_of: :decision

    # Lifecycle state is derived from the timestamps; these scopes and #state
    # are the single definition of what each state means
    scope :active, -> { where(resolved_at: nil) }
    scope :resolved, -> { where.not(resolved_at: nil).where(archived_at: nil) }
    scope :archived, -> { where.not(archived_at: nil) }

    validates :work_item, presence: true
    validates :namespace, presence: true
    validates :author, presence: true, on: :create
    validates :question, length: { maximum: TITLE_LENGTH_MAX }
    # Open decisions need the question; resolved-at-create decisions record
    # only the outcome (resolved_at is set before validation on that path)
    validates :question, presence: true, unless: :resolved_at?
    validates :description, length: { maximum: DESCRIPTION_LENGTH_MAX }
    validates :resolution_rationale, length: { maximum: RESOLUTION_RATIONALE_LENGTH_MAX }
    validates :source_link, length: { maximum: SOURCE_LINK_LENGTH_MAX }, addressable_url: true, allow_nil: true
    validates :discussion_id, format: { with: /\A\h{40}\z/ }, allow_nil: true
    # Only on the resolving transition: the FK is SET NULL on user deletion,
    # so persisted rows may legitimately have resolved_at without resolved_by
    validates :resolved_by, presence: true, if: -> { resolved_at? && resolved_at_changed? }

    before_validation :set_namespace

    # Used by GraphQL granular-token boundary extraction
    delegate :resource_parent, to: :work_item, allow_nil: true

    # Proposals are capped at MAX_OPTIONS_PER_DECISION. A written-in decision
    # is inserted as a selected option, and may take the extra slot if
    # proposals are already at max.
    def self.options_limit(selected:)
      selected ? MAX_OPTIONS_WITH_WRITE_IN : MAX_OPTIONS_PER_DECISION
    end

    def self.with_state(state)
      case state&.to_sym
      when :active then active
      when :resolved then resolved
      when :archived then archived
      else none
      end
    end

    def self.with_states(states)
      Array(states).map { |state| with_state(state) }.reduce(none, :or)
    end

    def state
      return :archived if archived_at?
      return :resolved if resolved_at?

      :active
    end

    # If the widget ever expands to epic work items, legacy epic notes are
    # stored against the Epic record and would fail the 'Issue' check here
    def resolvable_by_note?(note)
      !note.system? && note.for_issue? && note.noteable_id == work_item_id
    end

    # update_all: the selected flag has no validations, and per-record
    # update! would revalidate unrelated attributes on legacy rows
    def select_options!(ids)
      return if ids.empty?

      unordered_options.id_in(ids).update_all(selected: true, updated_at: Time.current)
      options.reset
    end

    def write_in_option!(content)
      transaction do
        unordered_options.where(selected: true).update_all(selected: false, updated_at: Time.current)
        options.reset
        options.create!(content: content, selected: true)
      end
    end

    private

    def unordered_options
      options.unscope(:order)
    end

    def set_namespace
      return if work_item.nil?
      return if work_item.namespace_id == namespace_id

      self.namespace_id = work_item.namespace_id
    end
  end
end

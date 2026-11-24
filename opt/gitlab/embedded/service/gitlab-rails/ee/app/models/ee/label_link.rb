# frozen_string_literal: true

module EE
  module LabelLink
    extend ActiveSupport::Concern

    LABEL_INDEXED_MODELS = %w[Epic Issue MergeRequest WorkItem].freeze

    prepended do
      after_destroy :maintain_target_elasticsearch!

      before_validation :rewrite_epic_type, on: :create
    end

    class_methods do
      def by_target_for_exists_query(target_type, arel_join_column, label_ids = nil)
        return super unless target_type == 'Epic'

        # Epic labels are stored as target_type = 'Issue' with the issue_id.
        super('Issue', ::Epic.arel_table['issue_id'], label_ids)
      end
    end

    private

    # Force the use of Epic's WorkItem ID and type
    def rewrite_epic_type
      return unless target
      return unless target_type == 'Epic'
      return unless target.is_a?(Epic)

      self.target_id = target.issue_id
      self.target_type = 'Issue'
    end

    def maintain_target_elasticsearch!
      object = target
      return if LABEL_INDEXED_MODELS.exclude?(object.class.name)

      self.class.current_transaction.after_commit { Elastic::ProcessBookkeepingService.track!(object) }
    end
  end
end

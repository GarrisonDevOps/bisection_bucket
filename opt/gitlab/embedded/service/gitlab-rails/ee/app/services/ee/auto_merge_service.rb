# frozen_string_literal: true

module EE
  module AutoMergeService
    extend ActiveSupport::Concern

    STRATEGY_MERGE_TRAIN = 'merge_train'

    # The auto-merge strategies that route a merge request through a merge train.
    MERGE_TRAIN_STRATEGIES = [
      STRATEGY_MERGE_TRAIN,
      ::AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS
    ].freeze

    EE_STRATEGIES = MERGE_TRAIN_STRATEGIES

    EE_STRATEGY_TO_CLASS_MAP = {
      STRATEGY_MERGE_TRAIN => AutoMerge::MergeTrainService,
      ::AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS =>
        AutoMerge::AddToMergeTrainWhenChecksPassService
    }.freeze

    class_methods do
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      override :all_strategies_ordered_by_preference
      def all_strategies_ordered_by_preference
        strong_memoize(:all_strategies_ordered_by_preference) do
          EE_STRATEGIES + super
        end
      end

      private

      def strategy_to_class_map
        super.merge(EE_STRATEGY_TO_CLASS_MAP)
      end
    end
  end
end

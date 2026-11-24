# frozen_string_literal: true

module EE
  module Groups # rubocop:disable Gitlab/BoundedContexts -- Extending existing module
    module RestoreService
      extend ::Gitlab::Utils::Override

      override :post_success
      def post_success
        super

        ::GitlabSubscriptions::FreeGroupUpgradeLinkCache.invalidate(current_user.id)
        # The indexed `active` field folds in deletion scheduling and is ancestor-aware,
        # so every descendant's document goes stale too.
        ::Search::Elastic::GroupActiveStateWorker.perform_async(resource.id)
      end
    end
  end
end

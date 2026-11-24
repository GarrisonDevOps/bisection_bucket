# frozen_string_literal: true

module Onboarding
  class AddOnSeatAssignmentIterableTriggerWorker # rubocop:disable Scalability/IdempotentWorker -- Don't rerun, else mass iterables created
    include ApplicationWorker

    data_consistency :delayed

    feature_category :onboarding

    # step 1 in adding another parameter:
    # https://docs.gitlab.com/ee/development/sidekiq/compatibility_across_updates.html#parameter-hash
    def perform(namespace_id, user_ids, params = {})
      @namespace = Namespace.find_by_id(namespace_id)
      return unless @namespace.present?

      @params = params

      User.left_join_user_detail.id_in(user_ids).find_each do |user|
        Onboarding::CreateIterableTriggerWorker
          .perform_async(
            ::Onboarding.add_on_seat_assignment_iterable_params(user, params['product_interaction'], namespace)
          )
      end
    end

    private

    attr_reader :namespace, :params
  end
end

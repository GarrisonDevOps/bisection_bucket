# frozen_string_literal: true

module Authn
  class CleanupScimGroupMembershipsWorker
    include ApplicationWorker

    feature_category :user_management

    data_consistency :sticky

    idempotent!

    loggable_arguments 0

    BATCH_SIZE = 1000

    def perform(scim_group_uid)
      return if scim_group_uid.blank?

      Authn::ScimGroupMembership.by_scim_group_uid(scim_group_uid).each_batch(of: BATCH_SIZE) do |batch|
        batch.delete_all
      end
    end
  end
end

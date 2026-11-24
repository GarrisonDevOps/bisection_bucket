# frozen_string_literal: true

module Authn
  class SyncScimIdentityRecordWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :user_management

    idempotent!

    def perform(args); end
  end
end

# frozen_string_literal: true

module Authn
  class SyncGroupScimTokenRecordWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :user_management

    idempotent!

    def perform(args); end
  end
end

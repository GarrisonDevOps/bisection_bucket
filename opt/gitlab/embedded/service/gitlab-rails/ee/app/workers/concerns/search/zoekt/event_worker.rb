# frozen_string_literal: true

module Search
  module Zoekt
    module EventWorker
      extend ActiveSupport::Concern

      included do
        include Search::Worker

        pause_control :zoekt
        sidekiq_options retry: 1

        deduplicate :until_executed, if_deduplicated: :reschedule_once

        private

        def logger
          @logger ||= ::Search::Zoekt::Logger.build
        end
      end
    end
  end
end

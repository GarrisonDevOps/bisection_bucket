# frozen_string_literal: true

module EE
  # This module is intended to encapsulate EE-specific model logic and be
  # prepended in the `Repositories::PostReceiveWorker`
  module Repositories
    module PostReceiveWorker
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :geo_log_update_event
      def geo_log_update_event(container)
        container.repository.log_geo_updated_event
      end
    end
  end
end

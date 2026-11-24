# frozen_string_literal: true

module EE
  module Ci
    module Metadatable
      extend ActiveSupport::Concern

      def secrets
        read_job_definition_attribute(:secrets, {}).deep_stringify_keys
      end

      def secrets?
        secrets.present?
      end
    end
  end
end

# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class EnforcementWithoutStorage < Enforcement
      private

      def in_pre_enforcement_phase?
        false
      end
    end
  end
end

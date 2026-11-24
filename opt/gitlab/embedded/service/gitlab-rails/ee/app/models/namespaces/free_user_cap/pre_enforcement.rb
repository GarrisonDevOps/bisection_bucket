# frozen_string_literal: true

module Namespaces
  module FreeUserCap
    class PreEnforcement
      def initialize(root_namespace)
        @root_namespace = root_namespace
      end

      def qualifies?
        return false if Feature.enabled?(:free_user_cap_without_storage_check, root_namespace)

        ::Namespaces::FreeUserCap::RootSize.new(root_namespace).above_size_limit?
      end

      private

      attr_reader :root_namespace
    end
  end
end

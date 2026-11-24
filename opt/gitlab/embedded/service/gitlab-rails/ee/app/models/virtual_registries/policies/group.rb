# frozen_string_literal: true

module VirtualRegistries
  module Policies
    class Group
      attr_reader :group

      delegate_missing_to :group

      def initialize(group)
        @group = group
      end
    end
  end
end

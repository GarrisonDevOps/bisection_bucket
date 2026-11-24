# frozen_string_literal: true

module Ai
  module ToolRules
    # The first-party client tools governance knows about for one root namespace. Resolved
    # once per namespace so the settings page, rule validation and the claim agree.
    class FirstPartyTools
      class << self
        def for(namespace)
          return none unless namespace
          return none unless Feature.enabled?(:duo_cli_first_party_tools, namespace.root_ancestor)

          new(Registry::FIRST_PARTY_CLIENT_TOOLS.keys)
        end

        def none
          @none ||= new([])
        end
      end

      attr_reader :names

      def initialize(names)
        @names = names.dup.freeze
      end

      def empty?
        names.empty?
      end

      def include?(tool_name)
        names.include?(tool_name)
      end
    end
  end
end

# frozen_string_literal: true

require 'set'

module DeclarativePolicy
  # A small DSL class used within a prevent_all { ... } block
  # to capture exception abilities.
  #
  # Usage:
  #   rule { some_condition }.prevent_all do
  #     except :read
  #     except :list
  #   end
  class PreventAllDsl
    attr_reader :exceptions

    def initialize
      @exceptions = Set.new
    end

    def except(*abilities)
      @exceptions.merge(abilities)
    end
  end
end

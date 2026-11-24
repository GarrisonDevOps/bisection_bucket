# frozen_string_literal: true

require 'arel'

module ClickHouse
  module Client
    module ArelExtensions
      module Nodes
        class Final < ::Arel::Nodes::Unary
        end
      end
    end
  end
end

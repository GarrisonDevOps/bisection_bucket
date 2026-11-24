# frozen_string_literal: true

module Sbom
  class DependencyAggregationPolicy < BasePolicy
    delegate { @subject.group }
  end
end

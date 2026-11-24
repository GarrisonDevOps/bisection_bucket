# frozen_string_literal: true

module Sbom
  class ComponentPolicy < BasePolicy
    rule { default }.enable :read_component
  end
end

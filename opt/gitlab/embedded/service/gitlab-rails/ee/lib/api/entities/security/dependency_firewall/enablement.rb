# frozen_string_literal: true

module API
  module Entities
    module Security
      module DependencyFirewall
        class Enablement < Grape::Entity
          # `enabled`, not `enforced`: enforcement_type already means warn-versus-enforce for a
          # policy, so reusing that word here would read as policy mode rather than availability.
          expose :enabled, documentation: { type: 'Boolean', example: true }
        end
      end
    end
  end
end

# frozen_string_literal: true

# Unnamed (as: nil): a machine-to-machine endpoint with no Rails/JS path-helper
# consumers. Naming it would emit an unused frontend path helper on every routes
# regeneration.
get 'cloud_connector/keys', to: 'cloud_connector/keys#keys', as: nil

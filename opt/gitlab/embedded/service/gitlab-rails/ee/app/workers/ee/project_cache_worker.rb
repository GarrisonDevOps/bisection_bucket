# frozen_string_literal: true

module EE
  # Skip undesirable writes in projects that are being replicated from a Geo
  # primary site or another cell
  #
  # This module is intended to encapsulate EE-specific methods
  # and be **prepended** in the `ProjectCacheWorker` class.
  module ProjectCacheWorker
    include Geo::SkipReplica
  end
end

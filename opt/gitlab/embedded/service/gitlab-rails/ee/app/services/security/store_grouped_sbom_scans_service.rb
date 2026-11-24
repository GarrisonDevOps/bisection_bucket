# frozen_string_literal: true

module Security
  class StoreGroupedSbomScansService < StoreGroupedScansService
    extend ::Gitlab::Utils::Override

    private

    override :store_scan_for
    def store_scan_for(artifact, deduplicate)
      StoreSbomScanService.execute(artifact, known_keys, deduplicate)
    end
  end
end

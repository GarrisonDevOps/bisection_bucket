# frozen_string_literal: true

module PackageMetadata
  class DataObjectFabricator
    include Enumerable

    def initialize(data_file:, sync_config:)
      @data_file = data_file
      @sync_config = sync_config
    end

    def each
      data_file.each do |data|
        obj = create_object(data)
        yield obj unless obj.nil?
      end
    end

    private

    attr_reader :data_file, :sync_config

    def create_object(data)
      data_object_class.create(data, sync_config.purl_type)
    rescue ArgumentError => e
      Gitlab::ErrorTracking.track_exception(e, message: 'Skipped malformed package metadata record',
        data_type: sync_config.data_type, purl_type: sync_config.purl_type, data: data)
      nil
    end

    def data_object_class
      if sync_config.cve_enrichment?
        DataObjects::CveEnrichment
      elsif sync_config.advisories?
        sync_config.v3? ? AdvisoryDataObjectV3 : AdvisoryDataObject
      elsif sync_config.v3?
        PackageDataObjectV3
      else
        CompressedPackageDataObject
      end
    end
  end
end

# frozen_string_literal: true

module Security
  module Ingestion
    module Tasks
      # Creates new `Vulnerabilities::FindingLink` records.
      class IngestFindingLinks < AbstractTask
        include Gitlab::Ingestion::BulkInsertableTask

        self.model = Vulnerabilities::FindingLink

        private

        # Important Note:
        #   This task sets no `unique_by`, so `Gitlab::Ingestion::BulkInsertableTask`
        #   inserts these rows in the order `attributes` returns them. Sort them here
        #   by the unique index (vulnerability_occurrence_id, name, url) so concurrent
        #   ingestion transactions lock them in a consistent order. The id sorts
        #   numerically, as the index does; the text columns are compared as strings
        #   because `name` is nullable.
        #   See gitlab-org/gitlab#603322 for more details.
        def attributes
          link_attributes.sort_by do |values|
            [values[:vulnerability_occurrence_id], values[:name].to_s, values[:url].to_s]
          end
        end

        def link_attributes
          finding_maps.flat_map do |finding_map|
            new_links_for(finding_map).map do |link|
              {
                vulnerability_occurrence_id: finding_map.finding_id,
                name: link.name,
                url: link.url
              }
            end
          end
        end

        def new_links_for(finding_map)
          existing_links = existing_finding_links[finding_map.finding_id].to_a
          existing_urls = existing_links.map(&:url)

          finding_map.report_finding.links.reject { |link| existing_urls.include?(link.url) }
        end

        def existing_finding_links
          @existing_finding_links ||= Vulnerabilities::FindingLink.by_finding_id(finding_ids)
                                                                  .group_by(&:vulnerability_occurrence_id)
        end

        def finding_ids
          finding_maps.map(&:finding_id)
        end
      end
    end
  end
end

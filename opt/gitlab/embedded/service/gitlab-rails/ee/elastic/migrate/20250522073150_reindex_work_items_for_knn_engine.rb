# frozen_string_literal: true

class ReindexWorkItemsForKnnEngine < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  skip_if -> { !valid_version? }

  def targets
    %w[WorkItem]
  end
end

private

def valid_version?
  helper.matching_distribution?(:opensearch, min_version: Search::Elastic::Types::WorkItem::LUCENE_MIN_VERSION)
end

def helper
  @helper ||= Search::Elastic::Helper.default
end

ReindexWorkItemsForKnnEngine.prepend ::Search::Elastic::MigrationObsolete

# frozen_string_literal: true

class RemoveEpicsIndex < Elastic::Migration
  include Search::Elastic::MigrationHelper

  retry_on_failure

  EPICS_INDEX_NAME = [::Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'epics'].join('-')

  def migrate
    remove_standalone_index(index_name: EPICS_INDEX_NAME)
  end

  def completed?
    !helper.index_exists?(index_name: EPICS_INDEX_NAME)
  end
end

RemoveEpicsIndex.prepend ::Search::Elastic::MigrationObsolete

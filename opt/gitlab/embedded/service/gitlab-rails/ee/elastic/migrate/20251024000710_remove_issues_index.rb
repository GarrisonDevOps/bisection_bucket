# frozen_string_literal: true

class RemoveIssuesIndex < Elastic::Migration
  include Search::Elastic::MigrationHelper

  retry_on_failure

  ISSUES_INDEX_NAME = [::Gitlab::CurrentSettings.elasticsearch_prefix, Rails.env, 'issues'].join('-')

  def migrate
    remove_standalone_index(index_name: ISSUES_INDEX_NAME)
  end

  def completed?
    !helper.index_exists?(index_name: ISSUES_INDEX_NAME)
  end
end

RemoveIssuesIndex.prepend ::Search::Elastic::MigrationObsolete

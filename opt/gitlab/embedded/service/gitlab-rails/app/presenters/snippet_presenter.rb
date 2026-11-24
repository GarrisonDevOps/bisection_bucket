# frozen_string_literal: true

class SnippetPresenter < Gitlab::View::Presenter::Delegated
  presents ::Snippet, as: :snippet

  def raw_url
    url_builder.build(snippet, raw: true)
  end

  delegator_override :ssh_url_to_repo
  def ssh_url_to_repo
    snippet.ssh_url_to_repo if snippet.repository_exists?
  end

  delegator_override :http_url_to_repo
  def http_url_to_repo
    snippet.http_url_to_repo if snippet.repository_exists?
  end

  def can_read_snippet?
    can?(current_user, :read_snippet, snippet)
  end

  def can_update_snippet?
    can?(current_user, :update_snippet, snippet)
  end

  def can_delete_snippet?
    can?(current_user, :delete_snippet, snippet)
  end

  def can_report_as_spam?
    snippet.submittable_as_spam_by?(current_user)
  end

  delegator_override :blob
  def blob
    return snippet.blob if snippet.empty_repo?

    blobs.first
  end
end

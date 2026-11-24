# frozen_string_literal: true

class WorkItemPresenter < IssuePresenter # rubocop:todo Gitlab/NamespacedClass -- WorkItem is not namespaced
  extend ::Gitlab::Utils::Override
  include ::Gitlab::Utils::StrongMemoize

  # WorkItem also includes StrongMemoize, so lint:static_verification_with_database
  # rejects this include as a delegator override unless it is allowlisted.
  delegator_override_with ::Gitlab::Utils::StrongMemoize # This module inclusion is expected. See https://gitlab.com/gitlab-org/gitlab/-/issues/352884.

  presents ::WorkItem, as: :work_item

  override :web_url
  def web_url
    return super unless work_item.show_as_work_item?

    work_item_url_helper(only_path: false)
  end

  override :web_path
  def web_path
    return super unless work_item.show_as_work_item?

    work_item_url_helper(only_path: true)
  end

  def duplicated_to_work_item_url
    return unless work_item.duplicated?
    return unless allowed_to_read_work_item?(work_item.duplicated_to)

    Gitlab::UrlBuilder.build(work_item.duplicated_to)
  end

  def moved_to_work_item_url
    return unless readable_moved_to_work_item

    Gitlab::UrlBuilder.build(readable_moved_to_work_item)
  end

  def moved_to_work_item_id
    readable_moved_to_work_item&.id
  end

  private

  def readable_moved_to_work_item
    return unless work_item.moved?
    return unless allowed_to_read_work_item?(work_item.moved_to)

    work_item.moved_to
  end
  strong_memoize_attr :readable_moved_to_work_item

  def allowed_to_read_work_item?(item)
    Ability.allowed?(current_user, :read_work_item, item)
  end

  def work_item_url_helper(only_path:)
    Gitlab::Routing.url_helpers.polymorphic_url(
      [work_item.resource_parent.owner_entity, work_item], only_path: only_path
    )
  end
end

WorkItemPresenter.prepend_mod_with('WorkItemPresenter')
